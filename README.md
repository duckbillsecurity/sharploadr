# 🔐 Encrypted Execution Loader with AMSI Bypass

This repository contains two PowerShell scripts:
1. **Encryption Script** - Encrypts a C# binary using AES-256.
2. **Decryption & Execution Script** - Decrypts and executes the binary **in memory** using **reflective loading**, with an **AMS bypass** to evade detection.

---

## 📌 1. Encryption Script (`Encrypt-Binary.ps1`)

This script encrypts a compiled C# executable using **AES-256 encryption** with a randomly generated IV. The output is a secure `.enc` file that can only be decrypted with the correct password.

### 🔹 How It Works:
- Uses **SHA-256** to derive a strong encryption key from a password.
- Generates a **random IV (Initialization Vector)** for added security.
- Encrypts the binary in **AES-CBC mode with PKCS7 padding**.
- Combines the IV + encrypted data into a single output file.

### 🔹 Usage:
```powershell
.\Encrypt-Binary.ps1 -InputFile "SharpEDRchecker.exe" -Password "StrongPassword123" -OutputFile "SharpEDRchecker.enc"
```

