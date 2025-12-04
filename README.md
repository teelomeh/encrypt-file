
# AES File Protect — README

## Overview
This project provides a secure file encryption and decryption tool using **AES‑256‑GCM** and **PBKDF2-HMAC-SHA256**.  
The program allows users to encrypt any text or binary file with a password-derived key.

## Features
- AES‑256‑GCM authenticated encryption  
- PBKDF2 password-based key derivation  
- Random salts and nonces  
- CLI interface for encrypt/decrypt  
- Password generator  
- Error handling and input validation  

## Usage

### Encrypt a file (interactive password)
```bash
python aes_file_protect.py encrypt input.txt output.bin
```

### Encrypt with generated password
```bash
python aes_file_protect.py encrypt input.txt output.bin --generate
```

### Decrypt a file
```bash
python aes_file_protect.py decrypt output.bin recovered.txt
```

### Decrypt with password provided on CLI
```bash
python aes_file_protect.py decrypt output.bin recovered.txt --password "MyPass123!"
```

## Security Notes
- Generated password must be stored securely.
- PBKDF2 iteration count can be adjusted with `--iterations`.
- Passing passwords via CLI is insecure; prefer interactive prompt.

## Requirements
```
python 3.8+
cryptography
```

Install dependencies:
```bash
pip install cryptography
```

## File Format Structure
```
MAGIC (4 bytes)
VERSION (1 byte)
salt_len (1 byte)
salt (salt_len bytes)
nonce_len (1 byte)
nonce (nonce_len bytes)
iterations (4 bytes)
ciphertext + tag
```

## License
MIT License
