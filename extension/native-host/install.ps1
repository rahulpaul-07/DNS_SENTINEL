# Install DNSentinel Native Host for Chrome/Edge on Windows

$ErrorActionPreference = "Stop"

$HostName = "com.dnssentinel.host"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# The path to the Python executable. Adjust if using a virtual environment.
$PythonExe = "python.exe"

$TargetDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\NativeMessagingHosts"
if (!(Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
}

$ManifestPath = "$TargetDir\$HostName.json"
$ScriptTarget = "$TargetDir\dnssentinel_host.py"
$BatTarget = "$TargetDir\dnssentinel_host.bat"

# Copy the python script
Copy-Item "$ScriptDir\dnssentinel_host.py" $ScriptTarget -Force

# Create a batch wrapper since Chrome on Windows requires an executable or bat file
Set-Content -Path $BatTarget -Value "@echo off`r`n$PythonExe `"$ScriptTarget`""

# Read the template, replace the path with the batch file, and write to target
$ManifestContent = Get-Content "$ScriptDir\$HostName.json" -Raw
# Replace "dnssentinel_host.py" with the bat file path, escaping backslashes for JSON
$EscapedPath = $BatTarget -replace '\\', '\\'
$ManifestContent = $ManifestContent -replace '"path": "dnssentinel_host.py"', "`"path`": `"$EscapedPath`""

Set-Content -Path $ManifestPath -Value $ManifestContent

# Register in Registry
$RegistryPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
if (!(Test-Path $RegistryPath)) {
    New-Item -Path "HKCU:\Software\Google\Chrome\NativeMessagingHosts" -Name $HostName -Force | Out-Null
}
Set-ItemProperty -Path $RegistryPath -Name "(default)" -Value $ManifestPath

Write-Host "Native messaging host installed successfully."
