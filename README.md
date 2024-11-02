# Crypt Tool Documentation

Version 001 - This is made as a cli app so scrpits can be used for batch processing. Many more features will be included in future. 

The `crypt` tool is a versatile command-line application that provides various cryptographic functionalities, including key generation, XOR encryption/decryption, byte scrambling, secure file erasure, and file analysis. It incorporates memory safety features to securely handle sensitive data.

**Note on One-Time Pad (OTP) Encryption:** The tool's XOR encryption function can be used to implement a form of One-Time Pad encryption when the key is truly random, at least as long as the message, kept secret, and never reused. OTP is theoretically unbreakable when these conditions are met. However, practical implementation requires careful management of key material.

## Available Commands
The tool provides the following commands:
- `keygen`: Generate cryptographic key files.
- `xor`: Perform XOR encryption or decryption on files.
- `scramble`: Randomly shuffle the bytes of a file.
- `erase`: Securely erase files by overwriting them with random data.
- `scan`: Analyze a file's byte frequencies and calculate entropy.

## Commands Overview

### 1. `keygen` Command
**Purpose:** Generate a key file of a specified size, either randomly or deterministically using a password.

#### Usage:
```sh
crypt keygen <size> --output-file <output_file> --mode <random|deterministic> [--password <password>]
```

#### Arguments:
- `<size>`: The size of the key file to generate. Examples:
  - `32bytes`
  - `20mb`
  - `5gb`
- `--output-file <output_file>`: The path where the generated key file will be saved. This file must not already exist.
- `--mode <random|deterministic>`: The mode of key generation.
  - `random`: Generates a key with random data.
  - `deterministic`: Generates a key based on a password.
- `--password <password>` (optional): Required if `--mode` is set to `deterministic`. This password is used to generate the deterministic key.

#### How It Works:
- **Random Mode**: Uses a secure random number generator to produce a key file of the specified size.
- **Deterministic Mode**: Derives a key from the provided password using the Argon2 key derivation function. The derived key is used to seed a ChaCha20 random number generator, and AES-256 in CTR mode is applied to enhance security.

#### Memory Safety:
- Sensitive data, such as derived keys and passwords, are securely zeroed out from memory after use.

#### Examples:
```sh
# Generate a 32-byte random key and save it to random_key.key
crypt keygen 32bytes --output-file random_key.key --mode random

# Generate a 20 MB deterministic key with a password
crypt keygen 20mb --output-file deterministic_key.key --mode deterministic --password mypassword
```

### 2. `xor` Command
**Purpose:** Perform XOR encryption or decryption on a file using a key file.

#### Usage:
```sh
crypt xor <input_file> <output_file> <key_file>
```

#### Arguments:
- `<input_file>`: The path to the input file you want to encrypt or decrypt.
- `<output_file>`: The path where the output (encrypted or decrypted) file will be saved. This file must not already exist.
- `<key_file>`: The path to the key file that will be used for the XOR operation. The key file must be at least as large as the input file.

#### How It Works:
The tool reads the input and key files into memory, performs a byte-wise XOR operation between the input data and the key data, and writes the result to the output file.

#### Memory Safety:
- Input data, key data, and processed data are securely zeroed out from memory after use.

#### Examples:
```sh
# Encrypt a file using a key
crypt xor mydocument.txt encrypted_output.bin mykey.key

# Decrypt a file using the same key
crypt xor encrypted_output.bin decrypted_document.txt mykey.key
```

### 3. `scramble` Command
**Purpose:** Randomly shuffle the bytes of a file.

#### Usage:
```sh
crypt scramble <input_file> [output_file] [--overwrite]
```

#### Arguments:
- `<input_file>`: The path to the input file you want to scramble.
- `output_file` (optional): The path where the scrambled output file will be saved.
- `--overwrite` (optional): If specified, the input file will be overwritten with the scrambled data.

#### Notes:
- Either an `output_file` or the `--overwrite` flag must be specified.

#### Memory Safety:
- The data buffer is securely zeroed out after scrambling to prevent any residual data from remaining in memory.

#### Examples:
```sh
# Scramble a file and write to a new file
crypt scramble input.txt scrambled_output.txt

# Scramble a file and overwrite the original file
crypt scramble input.txt --overwrite
```

### 4. `erase` Command
**Purpose:** Securely erase a file by overwriting it with random data.

#### Usage:
```sh
crypt erase <input_file> [--passes <number_of_passes>]
```

#### Arguments:
- `<input_file>`: The path to the file you want to securely erase.
- `--passes <number_of_passes>` (optional): Number of times to overwrite the file. Default is 1.

#### How It Works:
The tool overwrites the file with random data, reducing the likelihood of recovering the original data using forensic methods.

#### Memory Safety:
- Buffers used for holding random data are securely zeroed out after each pass.

#### Examples:
```sh
# Securely erase a file with 1 pass
crypt erase sensitive_data.txt

# Securely erase a file with 3 passes
crypt erase sensitive_data.txt --passes 3
```

### 5. `scan` Command
**Purpose:** Analyze a file's byte frequencies and calculate its Shannon entropy.

#### Usage:
```sh
crypt scan <input_file> [--output-file <report_file>]
```

#### Arguments:
- `<input_file>`: The path to the file you want to analyze.
- `--output-file <report_file>` (optional): The path where the analysis report will be saved. Defaults to `report.txt` if not specified.

#### How It Works:
The tool reads the input file, counts the frequency of each byte, and calculates Shannon entropy. Results are written to the specified report file.

#### Memory Safety:
- The data buffer is securely zeroed out after analysis to prevent any residual data from lingering in memory.

#### Examples:
```sh
# Analyze a file and save the report to 'report.txt'
crypt scan input_file.txt

# Analyze a file and specify a custom report file
crypt scan input_file.txt --output-file analysis_report.txt
```

## General Notes
- All commands check for existing output files to prevent accidental overwriting unless explicitly specified.
- Secure random number generators are used to ensure cryptographic security.
- Memory safety is enforced throughout using the `zeroize` crate to prevent sensitive data from lingering in memory.

## Security Considerations
- **XOR Encryption:** XOR encryption is not secure against modern cryptographic attacks, especially if the key is reused. Use proper key management for secure use.
- **One-Time Pad (OTP) Limitations:** Implementing OTP requires a truly random key that is as long as the message and never reused. Managing such keys securely can be challenging.
- **Byte Scrambling:** This is not a secure method of encryption; it only obfuscates data superficially.
- **Secure Erasure:** Due to hardware-level optimizations like wear leveling, secure file erasure might not guarantee that data is unrecoverable. For sensitive data, consider additional measures such as physical destruction.

For robust security, consider using established cryptographic protocols and tools designed for secure encryption and data handling.

