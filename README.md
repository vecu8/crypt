




Crypt Tool Documentation

 body {
 font-family: Arial, sans-serif;
 margin: 20px;
 }
 code {
 background-color: #f4f4f4;
 padding: 2px 4px;
 font-size: 90%;
 color: #c7254e;
 }
 pre {
 background-color: #f4f4f4;
 padding: 10px;
 overflow-x: auto;
 }
 h1, h2, h3, h4 {
 color: #333;
 }
 .command {
 margin-bottom: 30px;
 }
 ul {
 line-height: 1.6;
 }
 .details {
 margin-left: 20px;
 font-size: 90%;
 color: #555;
 }
 


Crypt Tool Documentation
========================


The `crypt` tool is a versatile command-line application that provides various cryptographic functionalities, including key generation, XOR encryption/decryption, byte scrambling, secure file erasure, and file analysis. It incorporates memory safety features to securely handle sensitive data.


**Note on One-Time Pad (OTP) Encryption:** The tool's XOR encryption function can be used to implement a form of One-Time Pad encryption when the key is truly random, at least as long as the message, kept secret, and never reused. OTP is theoretically unbreakable when these conditions are met. However, practical implementation requires careful management of key material.


Available Commands
------------------


The tool provides the following commands:


* `keygen`: Generate cryptographic key files.
* `xor`: Perform XOR encryption or decryption on files.
* `scramble`: Randomly shuffle the bytes of a file.
* `erase`: Securely erase files by overwriting them with random data.
* `scan`: Analyze a file's byte frequencies and calculate entropy.




1. `keygen` Command
-------------------


**Purpose:** Generate a key file of a specified size, either randomly or deterministically using a password.


### Usage:



```
crypt keygen <size> --output-file <output_file> --mode <random|deterministic> [--password <password>]
```

### Arguments:


* `<size>`: The size of the key file to generate. Examples:
	+ `32bytes`
	+ `20mb`
	+ `5gb`
* `--output-file <output_file>`: The path where the generated key file will be saved. This file must not already exist.
* `--mode <random|deterministic>`: The mode of key generation.
	+ `random`: Generates a key with random data.
	+ `deterministic`: Generates a key based on a password.
* `--password <password>` (optional): Required if `--mode` is set to `deterministic`. This password is used to generate the deterministic key.




### How It Works:


In **random** mode, the tool uses a secure random number generator to produce a key file of the specified size.


In **deterministic** mode, the tool derives a key from the provided password using the Argon2 key derivation function with specified parameters. The derived key is then used to seed a ChaCha20 random number generator, which produces the key data. Additionally, AES-256 in CTR mode is applied to further process the random data, enhancing security.


### Memory Safety:


* Sensitive data such as the derived key and password are securely zeroed out from memory after use using the `zeroize` crate.
* Buffers holding random data are also zeroed to prevent any leakage of sensitive information.


