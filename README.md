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

# 🔓 Decrypt & Execute Reflectively (with AMSI Bypass)

## **Overview**
`Decrypt-And-Execute-Reflective.ps1` is a **PowerShell script** that:
✅ **Bypasses AMSI** to prevent detection.  
✅ **Decrypts an AES-256 encrypted binary in memory** without writing to disk.  
✅ **Loads the decrypted assembly reflectively** and executes it **directly from memory**.  
✅ **Supports command-line arguments** for passing parameters to the decrypted executable.

---

## **📌 AMSI Bypass**
This script includes an **advanced AMSI bypass** that:
- **Dynamically loads `amsi.dll`**.
- **Uses `GetProcAddress` to locate `AmsiScanBuffer`**.
- **Patches the function in memory** using `VirtualProtect` & `Marshal.Copy()`.
- **Prevents AMSI from scanning** and detecting the execution.

---

## **🚀 Usage**
### **🔹 Basic Execution (No Arguments)**
```powershell
.\Decrypt-And-Execute-Reflective.ps1 -location "SharpEDRchecker.enc" -password "StrongPassword123"
