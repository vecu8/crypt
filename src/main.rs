use std::fs::{metadata, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes::Aes256;
use argon2::{self, Algorithm, Argon2, Params, Version};
use clap::{Parser, Subcommand};
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::seq::SliceRandom;
use rand::{rngs::OsRng, thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// A versatile crypto tool for key generation, byte scrambling,
/// secure file erasure, and file analysis.
#[derive(Parser)]
#[command(
    disable_help_flag = true,
    disable_version_flag = true,
    help_expected = false
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Keygen {
        size: String,
        #[arg(long)]
        output_file: String,
        #[arg(long)]
        mode: String,
        #[arg(long)]
        password: Option<String>,
    },
    DeterministicKey {
        size: String,
        #[arg(long)]
        output_file: String,
        #[arg(long)]
        input_string: String,
    },
    Scramble {
        input_file: String,
        output_file: Option<String>,
        #[arg(long)]
        overwrite: bool,
    },
    Erase {
        input_file: String,
        #[arg(long, default_value = "1")]
        passes: usize,
    },
    Scan {
        input_file: String,
        #[arg(long)]
        output_file: Option<String>,
    },
}

fn main() -> io::Result<()> {
    let cli_result = Cli::try_parse();

    match cli_result {
        Ok(cli) => match cli.command {
            Commands::Keygen {
                size,
                output_file,
                mode,
                password,
            } => {
                keygen(size, output_file, mode, password)?;
            }
            Commands::DeterministicKey {
                size,
                output_file,
                input_string,
            } => {
                deterministic_keygen(size, output_file, input_string)?;
            }
            Commands::Scramble {
                input_file,
                output_file,
                overwrite,
            } => {
                scramble(&input_file, output_file.as_deref(), overwrite)?;
            }
            Commands::Erase { input_file, passes } => {
                erase(&input_file, passes)?;
            }
            Commands::Scan {
                input_file,
                output_file,
            } => {
                scan(&input_file, output_file.as_deref())?;
            }
        },
        Err(_) => {
            eprintln!("Usage: crypt <COMMAND>");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn keygen(
    size_arg: String,
    output_file: String,
    mode: String,
    password: Option<String>,
) -> io::Result<()> {
    if mode != "random" && mode != "deterministic" {
        eprintln!("Error: Mode must be 'random' or 'deterministic'.");
        eprintln!("Usage: crypt <COMMAND>");
        std::process::exit(1);
    }

    if mode == "deterministic" && password.is_none() {
        eprintln!("Error: --password is required in deterministic mode.");
        eprintln!("Usage: crypt <COMMAND>");
        std::process::exit(1);
    }

    let size_in_bytes = match parse_size(&size_arg) {
        Ok(size) => size,
        Err(err) => {
            eprintln!("Error parsing size: {}", err);
            std::process::exit(1);
        }
    };

    if Path::new(&output_file).exists() {
        eprintln!("Error: File '{}' already exists.", output_file);
        std::process::exit(1);
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_file)?;

    let buffer_size = 1024 * 1024;
    let mut buffer = vec![0u8; buffer_size];
    let mut bytes_written = 0;

    if mode == "random" {
        let mut rng = OsRng;

        while bytes_written < size_in_bytes {
            let bytes_to_write = std::cmp::min(buffer_size, size_in_bytes - bytes_written);
            rng.fill_bytes(&mut buffer[..bytes_to_write]);
            file.write_all(&buffer[..bytes_to_write])?;
            bytes_written += bytes_to_write;
        }
    } else {
        const SALT: &[u8] = b"your_salt_here";
        const IV: [u8; 16] = [
            12, 85, 240, 66, 171, 19, 55, 129, 200, 33, 147, 89, 78, 123, 211, 34,
        ];
        const ARGON2_MEMORY_COST: u32 = 65536;
        const ARGON2_TIME_COST: u32 = 3;
        const ARGON2_PARALLELISM: u32 = 1;
        type Aes256Ctr = ctr::Ctr64BE<Aes256>;

        let params = Params::new(
            ARGON2_MEMORY_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(32),
        )
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to create Argon2 parameters: {}", e),
            )
        })?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let password_str = password.unwrap();
        let password_bytes = password_str.as_bytes();

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password_bytes, SALT, &mut derived_key)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Failed to derive key with Argon2: {}", e),
                )
            })?;

        let mut cipher = Aes256Ctr::new(&derived_key.into(), &IV.into());

        let mut rng = ChaCha20Rng::from_seed(derived_key);

        while bytes_written < size_in_bytes {
            let bytes_to_write = std::cmp::min(buffer_size, size_in_bytes - bytes_written);
            rng.fill_bytes(&mut buffer[..bytes_to_write]);
            cipher.apply_keystream(&mut buffer[..bytes_to_write]);
            file.write_all(&buffer[..bytes_to_write])?;
            bytes_written += bytes_to_write;
        }

        // Securely zero sensitive data
        derived_key.zeroize();
        buffer.zeroize();
    }

    println!(
        "Successfully generated '{}' with size {} bytes.",
        output_file, size_in_bytes
    );

    Ok(())
}

fn deterministic_keygen(
    size_arg: String,
    output_file: String,
    input_string: String,
) -> io::Result<()> {
    // Parse size
    let size_in_bytes = match parse_size(&size_arg) {
        Ok(size) => size,
        Err(err) => {
            eprintln!("Error parsing size: {}", err);
            std::process::exit(1);
        }
    };

    // Check if output file exists
    if Path::new(&output_file).exists() {
        eprintln!("Error: File '{}' already exists.", output_file);
        std::process::exit(1);
    }

    // Hash the input string to create a seed
    let mut hasher = Sha256::new();
    hasher.update(input_string.as_bytes());
    let hash = hasher.finalize();

    let seed: [u8; 32] = hash.into();

    let mut rng = ChaCha20Rng::from_seed(seed);

    // Generate key data
    let buffer_size = 1024 * 1024;
    let mut buffer = vec![0u8; buffer_size];
    let mut bytes_written = 0;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_file)?;

    while bytes_written < size_in_bytes {
        let bytes_to_write = std::cmp::min(buffer_size, size_in_bytes - bytes_written);
        rng.fill_bytes(&mut buffer[..bytes_to_write]);
        file.write_all(&buffer[..bytes_to_write])?;
        bytes_written += bytes_to_write;
    }

    // Securely zero the buffer
    buffer.zeroize();

    println!(
        "Successfully generated '{}' with size {} bytes.",
        output_file, size_in_bytes
    );

    Ok(())
}

fn scramble(
    input_file: &str,
    output_file: Option<&str>,
    overwrite: bool,
) -> io::Result<()> {
    let output_path = if let Some(output_file) = output_file {
        let path = Path::new(output_file);
        if path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Error: File '{}' already exists.", output_file),
            ));
        }
        Some(path.to_path_buf())
    } else {
        if !overwrite {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Either specify an output file or use the --overwrite flag.",
            ));
        }
        None
    };

    let mut input_handle = File::open(input_file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to open input file '{}': {}", input_file, e),
        )
    })?;

    let mut data = Vec::new();
    input_handle.read_to_end(&mut data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to read input file '{}': {}", input_file, e),
        )
    })?;

    if data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Input file '{}' is empty. Nothing to scramble.",
                input_file
            ),
        ));
    }

    let mut rng = thread_rng();
    data.shuffle(&mut rng);

    if let Some(output_path) = output_path {
        let mut output_handle = File::create(&output_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create output file '{}': {}", output_path.display(), e),
            )
        })?;
        output_handle.write_all(&data).map_err(|e| {
            io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "Failed to write to output file '{}': {}",
                    output_path.display(),
                    e
                ),
            )
        })?;

        println!(
            "Successfully scrambled the bytes in '{}', output written to '{}'.",
            input_file,
            output_path.display()
        );
    } else {
        let mut output_handle = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(input_file)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to overwrite input file '{}': {}", input_file, e),
                )
            })?;
        output_handle.write_all(&data).map_err(|e| {
            io::Error::new(
                io::ErrorKind::WriteZero,
                format!("Failed to write to input file '{}': {}", input_file, e),
            )
        })?;

        println!(
            "Successfully scrambled the bytes in '{}', original file overwritten.",
            input_file
        );
    }

    // Securely zero the data buffer
    data.zeroize();

    Ok(())
}

fn erase(input_file: &str, passes: usize) -> io::Result<()> {
    if passes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Number of passes must be at least 1.",
        ));
    }

    let file_size = metadata(input_file)?.len();

    for pass in 1..=passes {
        let mut file_handle = OpenOptions::new()
            .write(true)
            .open(input_file)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Failed to open input file '{}': {}", input_file, e),
                )
            })?;

        let buffer_size = 1024 * 1024;
        let mut buffer = vec![0u8; buffer_size];
        let mut rng = OsRng;
        let mut bytes_written = 0;

        file_handle.seek(SeekFrom::Start(0))?;

        while bytes_written < file_size {
            let bytes_to_write =
                std::cmp::min(buffer_size as u64, file_size - bytes_written) as usize;
            rng.fill_bytes(&mut buffer[..bytes_to_write]);
            file_handle.write_all(&buffer[..bytes_to_write])?;
            bytes_written += bytes_to_write as u64;
        }

        // Securely zero the buffer
        buffer.zeroize();

        if passes > 1 {
            println!("Completed pass {} of {}.", pass, passes);
        }
    }

    println!("Successfully erased the file '{}'.", input_file);

    // Optionally, you can delete the file after overwriting
    // std::fs::remove_file(input_file)?;

    Ok(())
}

fn scan(input_file: &str, output_file: Option<&str>) -> io::Result<()> {
    if !Path::new(input_file).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("File '{}' does not exist.", input_file),
        ));
    }

    // Open the file in read-only mode
    let file = File::open(&input_file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Failed to open file '{}': {}", input_file, e),
        )
    })?;

    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();

    // Read the entire file into the buffer
    reader.read_to_end(&mut buffer).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to read file '{}': {}", input_file, e),
        )
    })?;

    // Initialize a frequency array for all 256 byte values
    let mut frequencies = [0u64; 256];

    for &byte in &buffer {
        frequencies[byte as usize] += 1;
    }

    // Determine the report file name
    let report_path = if let Some(output_file) = output_file {
        let path = Path::new(output_file);
        if path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Error: Report file '{}' already exists.", output_file),
            ));
        }
        path.to_path_buf()
    } else {
        Path::new("report.txt").to_path_buf()
    };

    // Prepare to write the report
    let report = File::create(&report_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Failed to create report file '{}': {}", report_path.display(), e),
        )
    })?;

    let mut writer = io::BufWriter::new(report);

    // Write the header
    writeln!(writer, "Binary Character Frequencies:\n").map_err(|e| {
        io::Error::new(
            io::ErrorKind::WriteZero,
            format!("Failed to write to report file '{}': {}", report_path.display(), e),
        )
    })?;

    // Write each byte and its count
    for (byte, &count) in frequencies.iter().enumerate() {
        // Display byte in hexadecimal for better readability
        writeln!(writer, "Byte {:02X} ({}): {}", byte, byte, count).map_err(|e| {
            io::Error::new(
                io::ErrorKind::WriteZero,
                format!("Failed to write to report file '{}': {}", report_path.display(), e),
            )
        })?;
    }

    // Add a separator
    writeln!(writer, "\nEntropy and Randomness Analysis:\n").map_err(|e| {
        io::Error::new(
            io::ErrorKind::WriteZero,
            format!("Failed to write to report file '{}': {}", report_path.display(), e),
        )
    })?;

    // Calculate entropy
    let entropy = calculate_entropy(&frequencies, buffer.len() as f64);
    writeln!(writer, "Shannon Entropy: {:.4} bits per byte", entropy).map_err(|e| {
        io::Error::new(
            io::ErrorKind::WriteZero,
            format!("Failed to write to report file '{}': {}", report_path.display(), e),
        )
    })?;

    // Additional randomness analysis can be added here
    // For example, Chi-Square test, Runs test, etc.

    writeln!(
        writer,
        "\nInterpretation:\n\
        - Entropy close to 8 bits per byte indicates high randomness.\n\
        - Lower entropy suggests patterns or redundancy in the data."
    )
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::WriteZero,
            format!("Failed to write to report file '{}': {}", report_path.display(), e),
        )
    })?;

    println!(
        "Analysis complete. Report saved to '{}'.",
        report_path.display()
    );

    // Securely zero the buffer
    buffer.zeroize();

    Ok(())
}

/// Calculates the Shannon entropy of the data.
fn calculate_entropy(frequencies: &[u64; 256], total: f64) -> f64 {
    frequencies.iter().fold(0.0, |acc, &count| {
        if count == 0 {
            acc
        } else {
            let p = count as f64 / total;
            acc - p * p.log2()
        }
    })
}

fn parse_size(size_str: &str) -> Result<usize, String> {
    let size_str = size_str.to_lowercase();

    let (number_part, unit) = size_str
        .trim()
        .chars()
        .partition::<String, _>(|c| c.is_digit(10));

    let size: usize = number_part
        .parse()
        .map_err(|_| "Invalid number format".to_string())?;

    let bytes = match unit.as_str() {
        "b" | "bytes" => size,
        "kb" => size * 1024,
        "mb" => size * 1024 * 1024,
        "gb" => size * 1024 * 1024 * 1024,
        _ => return Err("Unknown unit".to_string()),
    };

    Ok(bytes)
}
