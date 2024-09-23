
# ProcessInjectps1_multicrypt

**A Python script that encrypts shellcode using AES, Caesar cipher, RC4, or XOR encryption and generates a PowerShell script for process injection. The generated PowerShell script decrypts the shellcode at runtime and injects it into a remote process (e.g., `explorer.exe`).**

## 🔑 Key Features:
- **Supports Multiple Encryption Methods**: Encrypts shellcode using AES (256-bit), Caesar cipher, RC4, or XOR encryption methods.
- **PowerShell Template Generation**: Automatically generates a PowerShell script that includes decryption logic and process injection code for the chosen encryption method.
- **Process Injection**: The generated PowerShell script injects the decrypted shellcode into a remote process (e.g., `explorer.exe`) using Windows API functions such as `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread`.

## 📝 Usage:

### Command to Run the Script:
```bash
python3 ProcessInjectps1_multicrypt.py <shellcode.bin> <output.ps1> <method>
```

## Example 

```bash
python3 ProcessInjectps1_multicrypt.py shellcode.bin process_inject.ps1 AES
```

This command encrypts the shellcode in shellcode.bin using AES and generates a PowerShell file (process_inject.ps1) with the decryption logic and process injection code.

🛠 Supported Encryption Methods:
## AES Encryption:

Uses 256-bit AES in CBC mode with a randomly generated IV and key.
The generated PowerShell script includes AES decryption logic to decrypt the shellcode at runtime.

## Caesar Cipher:

A simple shift cipher that increments the byte value by a set amount (e.g., 3).
The PowerShell script will contain logic to reverse the Caesar cipher and retrieve the original shellcode.

## RC4 Encryption:

Uses RC4 stream cipher with a randomly generated 128-bit key.
The PowerShell script includes RC4 decryption logic to decrypt the shellcode at runtime.

## XOR Encryption:

Uses XOR encryption with a single-byte key.
The PowerShell script contains logic to decrypt the XOR-encrypted shellcode.

## 🖥️ Process Injection:
Once the shellcode is decrypted in memory, the PowerShell script uses standard Windows API functions to inject the shellcode into a target process (e.g., explorer.exe):

VirtualAllocEx: Allocates memory in the target process.
WriteProcessMemory: Writes the decrypted shellcode to the allocated memory.
CreateRemoteThread: Executes the shellcode in the target process.
