# Encrypt-Binary.ps1

<#
.SYNOPSIS
    Encrypts a specified executable using AES encryption.

.DESCRIPTION
    This script takes an input executable file, encrypts it using AES encryption with a provided password,
    and saves the encrypted binary to a specified output file.

.PARAMETER InputFile
    The full path to the input executable (.exe) file to be encrypted.

.PARAMETER OutputFile
    The full path where the encrypted binary will be saved.

.PARAMETER Password
    The password used to derive the encryption key.

.EXAMPLE
    .\Encrypt-Binary.ps1 -InputFile "C:\Apps\YourProgram.exe" -OutputFile "C:\Encrypted\YourProgram.enc" -Password "StrongPassword123"
#>

param (
    [Parameter(Mandatory = $true, HelpMessage = "Path to the input executable file.")]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$InputFile,

    [Parameter(Mandatory = $true, HelpMessage = "Path to save the encrypted file.")]
    [string]$OutputFile,

    [Parameter(Mandatory = $true, HelpMessage = "Password for encryption.")]
    [string]$Password
)

try {
    # Generate a 256-bit key from the password using SHA256
    Write-Verbose "Generating encryption key from password."
    $Key = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password))

    # Generate a random IV (Initialization Vector)
    Write-Verbose "Generating random Initialization Vector (IV)."
    $IV = New-Object byte[] 16
    [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($IV)

    # Read the input file
    Write-Verbose "Reading input file: $InputFile"
    $PlainBytes = [IO.File]::ReadAllBytes($InputFile)

    # Encrypt the bytes using AES
    Write-Verbose "Encrypting the input file."
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Key = $Key
    $Aes.IV = $IV
    $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $Encryptor = $Aes.CreateEncryptor()
    $EncryptedBytes = $Encryptor.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)

    # Combine IV and encrypted bytes for storage
    Write-Verbose "Combining IV with encrypted data."
    $CombinedBytes = $IV + $EncryptedBytes

    # Save the combined bytes to the output file
    Write-Verbose "Saving encrypted data to: $OutputFile"
    [IO.File]::WriteAllBytes($OutputFile, $CombinedBytes)

    Write-Output "Encryption complete. Encrypted file saved to $OutputFile"
}
catch {
    Write-Error "Encryption failed: $_"
    exit 1
}
