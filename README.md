# 🔐 TriLock

*TriLock* is a multi-layered hybrid file encryption tool that combines the strengths of classical and modern cryptography. It uses a layered approach with *Autokey Cipher, **AES, and **RSA* to provide secure and flexible encryption and decryption of text files.

---

## ✨ Features

- 🔒 *Three-layer encryption*: Classical + Symmetric + Asymmetric
- 📁 *File-based input/output* for easy integration
- 💻 *Tkinter GUI* for non-technical users
- 📦 Outputs encrypted ciphertext, RSA-encrypted AES key, and Autokey key
- 🔓 Seamless decryption pipeline with integrity checks

---

## 🔧 How It Works

1. *Autokey Cipher* encrypts the plaintext for a light obfuscation layer.
2. *AES* encrypts the result using a randomly generated symmetric key.
3. *RSA* encrypts the AES key, enabling secure key exchange.

The process is fully reversible and secure.

---

## 🖥 GUI Preview

TriLock includes a simple GUI using Python’s tkinter:

- 📤 Select plaintext file for encryption
- 🔐 Save encrypted file and keys
- 🔓 Decrypt files in one click
