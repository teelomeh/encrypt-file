#!/usr/bin/env python3

"""
aes_file_protect.py

Encrypts/decrypts files using AES-256-GCM with password-based key derivation (PBKDF2-HMAC-SHA256).

Usage examples:
  Encrypt with interactive password:
    python aes_file_protect.py encrypt input.txt output.bin

  Encrypt with generated password:
    python aes_file_protect.py encrypt input.txt output.bin --generate

  Decrypt:
    python aes_file_protect.py decrypt output.bin recovered.txt

Design notes:
  - Output file format (binary):
      [4 bytes magic 'AFP1'] [1 byte version]
      [1 byte salt_len][salt bytes]
      [1 byte nonce_len][nonce bytes]
      [4 bytes iterations (big-endian)]
      [remaining bytes = ciphertext + tag (as produced by AESGCM.encrypt)]
  - Uses AESGCM from cryptography.hazmat.primitives.ciphers.aead for AEAD encryption.
  - Derives 32-byte key via PBKDF2-HMAC-SHA256.
"""

import argparse
import os
import struct
import secrets
import sys
import getpass
from typing import Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import constant_time

MAGIC = b'AFP1'  # file magic for "AES File Protect v1"
VERSION = 1
DEFAULT_ITERATIONS = 200_000  # pbkdf2 iterations (tune for target hardware)
SALT_LEN = 16
NONCE_LEN = 12  # recommended for GCM


def derive_key(password: bytes, salt: bytes, iterations: int = DEFAULT_ITERATIONS, length: int = 32) -> bytes:
    """
    Derive a symmetric key from password using PBKDF2-HMAC-SHA256.
    - password: password bytes
    - salt: salt bytes (must be random and stored with ciphertext)
    - iterations: PBKDF2 iteration count
    - length: desired key length (32 bytes => AES-256)
    """
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


def encrypt_file(in_path: str, out_path: str, password: bytes, iterations: int = DEFAULT_ITERATIONS) -> None:
    """
    Encrypt the file at in_path and write binary package to out_path.
    The package contains salt, nonce, iterations, and ciphertext+tag.
    """
    # Read plaintext
    with open(in_path, 'rb') as f:
        plaintext = f.read()

    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key(password, salt, iterations=iterations)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_LEN)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # Compose file format
    # magic (4) | version(1) | salt_len(1) | salt | nonce_len(1) | nonce | iterations(4) | ciphertext...
    with open(out_path, 'wb') as f:
        f.write(MAGIC)
        f.write(struct.pack('!B', VERSION))
        f.write(struct.pack('!B', len(salt)))
        f.write(salt)
        f.write(struct.pack('!B', len(nonce)))
        f.write(nonce)
        f.write(struct.pack('!I', iterations))
        f.write(ciphertext)

    # wipe sensitive variables (best-effort)
    _zero_bytes(key)


def decrypt_file(in_path: str, out_path: str, password: bytes) -> None:
    """
    Read encrypted package from in_path, derive key from salt and password,
    decrypt and write plaintext to out_path. Raises ValueError on auth failure.
    """
    with open(in_path, 'rb') as f:
        data = f.read()

    offset = 0
    if data[offset:offset+4] != MAGIC:
        raise ValueError("Input file format not recognized (bad magic).")
    offset += 4

    version = data[offset]
    offset += 1
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}")

    salt_len = data[offset]
    offset += 1
    salt = data[offset:offset+salt_len]
    offset += salt_len

    nonce_len = data[offset]
    offset += 1
    nonce = data[offset:offset+nonce_len]
    offset += nonce_len

    iterations = struct.unpack('!I', data[offset:offset+4])[0]
    offset += 4

    ciphertext = data[offset:]

    key = derive_key(password, salt, iterations=iterations)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        # Authentication failure or other crypto error
        raise ValueError("Decryption failed. Wrong password or corrupted file.") from e

    with open(out_path, 'wb') as f:
        f.write(plaintext)

    _zero_bytes(key)


def _zero_bytes(b: bytes):
    """
    Best-effort attempt to overwrite bytes in memory. Python may not guarantee this.
    Provided to show intent of minimizing lifetime of secrets.
    """
    try:
        if isinstance(b, bytearray):
            for i in range(len(b)):
                b[i] = 0
        elif isinstance(b, bytes):
            # cannot mutate bytes, so create a bytearray copy and zero it
            ba = bytearray(b)
            for i in range(len(ba)):
                ba[i] = 0
    except Exception:
        pass


def generate_password(length: int = 24) -> str:
    """Generate a URL-safe strong password containing letters, digits, and punctuation."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}<>?,."
    # Use secrets.choice for cryptographic randomness
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def ask_password(confirm: bool = True) -> bytes:
    """Prompt user for password without echo. Optionally confirm."""
    pw1 = getpass.getpass("Enter password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if not constant_time.bytes_eq(pw1.encode('utf-8'), pw2.encode('utf-8')):
            raise ValueError("Passwords do not match.")
    return pw1.encode('utf-8')


def main():
    parser = argparse.ArgumentParser(description="AES file encrypt/decrypt (AES-256-GCM + PBKDF2).")
    sub = parser.add_subparsers(dest='command', required=True)

    enc = sub.add_parser('encrypt', help='Encrypt a file')
    enc.add_argument('infile', help='Input plaintext file')
    enc.add_argument('outfile', help='Output encrypted file')
    enc.add_argument('--password', '-p', help='Password (WARNING: passing password on CLI can be insecure).')
    enc.add_argument('--generate', '-g', action='store_true', help='Auto-generate a strong password and print it (do not store in code).')
    enc.add_argument('--iterations', type=int, default=DEFAULT_ITERATIONS, help='PBKDF2 iteration count (default %(default)s)')

    dec = sub.add_parser('decrypt', help='Decrypt a file')
    dec.add_argument('infile', help='Input encrypted file')
    dec.add_argument('outfile', help='Output recovered plaintext file')
    dec.add_argument('--password', '-p', help='Password (WARNING: passing password on CLI can be insecure).')

    args = parser.parse_args()

    try:
        if args.command == 'encrypt':
            if args.generate:
                generated = generate_password()
                print("Generated password (save it securely):")
                print(generated)
                password = generated.encode('utf-8')
            elif args.password:
                # CLI provided password (insecure) but allowed
                password = args.password.encode('utf-8')
            else:
                password = ask_password(confirm=True)

            encrypt_file(args.infile, args.outfile, password, iterations=args.iterations)
            print(f"Encrypted '{args.infile}' -> '{args.outfile}'")

        elif args.command == 'decrypt':
            if args.password:
                password = args.password.encode('utf-8')
            else:
                password = ask_password(confirm=False)

            decrypt_file(args.infile, args.outfile, password)
            print(f"Decrypted '{args.infile}' -> '{args.outfile}'")

    except Exception as e:
        print("Error:", e, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
