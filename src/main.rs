use std::fs::{metadata, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes::Aes256;
use argon2::{self, Algorithm, Argon2, Params, Version};
use clap::{Parser, Subcommand};
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::seq::SliceRandom;
use rand::{rngs::OsRng, thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

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
    Xor {
        input_file: String,
        output_file: String,
        key_file: String,
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
            Commands::Xor {
                input_file,
                output_file,
                key_file,
            } => {
                xor_process(&input_file, &output_file, &key_file)?;
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

fn xor_process(input_file: &str, output_file: &str, key_file: &str) -> io::Result<()> {
    let input_path = Path::new(input_file);
    let output_path = Path::new(output_file);
    let key_path = Path::new(key_file);

    if output_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("Error: File '{}' already exists.", output_file),
        ));
    }

    let mut key_handle = File::open(&key_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Key file '{}' not found or cannot be opened: {}",
                key_path.display(),
                e
            ),
        )
    })?;
    let mut key = Vec::new();
    key_handle.read_to_end(&mut key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to read key file '{}': {}", key_path.display(), e),
        )
    })?;

    if key.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Key file '{}' is empty. Please provide a valid key.",
                key_path.display()
            ),
        ));
    }

    let mut input_handle = File::open(&input_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Unable to open input file '{}': {}",
                input_path.display(),
                e
            ),
        )
    })?;
    let mut input_data = Vec::new();
    input_handle.read_to_end(&mut input_data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to read input file '{}': {}", input_path.display(), e),
        )
    })?;

    if input_data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Input file '{}' is empty. Nothing to process.",
                input_path.display()
            ),
        ));
    }

    if key.len() < input_data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Key is shorter than input data. Please provide a key of sufficient length.",
        ));
    }

    let mut processed_data = input_data
        .iter()
        .zip(key.iter())
        .map(|(&data_byte, &key_byte)| data_byte ^ key_byte)
        .collect::<Vec<u8>>();

    let mut output_handle = File::create(&output_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Unable to create output file '{}': {}",
                output_path.display(),
                e
            ),
        )
    })?;
    output_handle.write_all(&processed_data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::WriteZero,
            format!(
                "Failed to write to output file '{}': {}",
                output_path.display(),
                e
            ),
        )
    })?;

    // Securely zero sensitive data
    key.zeroize();
    input_data.zeroize();
    processed_data.zeroize();

    let input_size = metadata(&input_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Unable to read input file metadata '{}': {}",
                input_path.display(),
                e
            ),
        )
    })?
    .len();
    let output_size = metadata(&output_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Unable to read output file metadata '{}': {}",
                output_path.display(),
                e
            ),
        )
    })?
    .len();
    if input_size != output_size {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Error: Output file size does not match input file size.",
        ));
    }

    println!("Operation completed successfully.");

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
