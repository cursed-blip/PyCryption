# Pycryption 🔒

[![Pycryption](https://img.shields.io/badge/Pycryption-Lightweight%20Encryption-brightgreen?style=flat-square)](#)
[![Latest Stable Version](https://img.shields.io/badge/version-2.0.2-blue?style=flat-square)](#)
[![Discord](https://img.shields.io/badge/Discord-Join%20the%20Community-7289DA?style=flat-square)](https://discord.gg/jmHNWTrJ)

## Features ✨

- **Lightweight & Fast**: ~98% lighter than AES, minimal CPU usage  
- **Improved Security**: New built-in tag-based integrity system (lightweight HMAC-like)  
- **File Encryption**: Encrypt any file with `--encrypt --file <filename>`  
- **File Decryption**: Decrypt `.enc` files to `.dec` with `--decrypt --file <filename>`  
- **Interactive Text Mode**: Encrypt/decrypt text directly in the console  
- **Custom Tokens**: Easily extendable token list for encryption  
- **Nonce & Seed Support**: Random or fixed seed for deterministic encryption  
- **Benchmark Mode**: Measure Pycryption's encryption/decryption speed with `--benchmark`  
- **Secure Enough for Simple Use**: Great for lightweight projects or local data  

## Usage 🛠️

```bash
# Encrypt a file
python pycryption.py --encrypt --file example.txt

# Decrypt a file
python pycryption.py --decrypt --file example.txt.enc

# Interactive text encryption
python pycryption.py

# Run benchmark test
python pycryption.py --benchmark
