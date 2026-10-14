# Registers ClipBridge to start hidden at logon and connect to your Mac.
#   .\install-startup.ps1 -MacHost my-mac -Key <passphrase> [-Exe C:\Tools\clipbridge.exe]
# The key is saved to %LOCALAPPDATA%\ClipBridge\key.txt, readable only by you (and SYSTEM),
# and the task passes --key-file so the key never appears on a command line.
# Remove with:  Unregister-ScheduledTask -TaskName ClipBridge -Confirm:$false
param(
    [Parameter(Mandatory)] [string] $MacHost,
    [Parameter(Mandatory)] [string] $Key,
    [string] $Exe = "$env:LOCALAPPDATA\ClipBridge\clipbridge.exe"
)

$ErrorActionPreference = "Stop"

if ($Key.Trim().Length -lt 12) { throw "The key must be at least 12 characters. Generate one with: clipbridge genkey" }

$dataDir = "$env:LOCALAPPDATA\ClipBridge"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

if (-not (Test-Path $Exe)) {
    $dir = Split-Path $Exe
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $here = Join-Path $PSScriptRoot "clipbridge.exe"
    if (Test-Path $here) { Copy-Item $here $Exe } else { throw "clipbridge.exe not found at $Exe or next to this script" }
}

# Create the key file empty, lock it down, and only then write the key into it.
# /inheritance:r drops inherited entries; /grant:r leaves exactly the current user and SYSTEM.
$keyFile = Join-Path $dataDir "key.txt"
if (-not (Test-Path $keyFile)) { New-Item -ItemType File -Path $keyFile | Out-Null }
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls $keyFile /inheritance:r /grant:r "*${me}:(F)" "*S-1-5-18:(F)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls could not restrict access to $keyFile" }
# UTF-8 without a byte order mark, no trailing newline.
[System.IO.File]::WriteAllText($keyFile, $Key.Trim())

$log = "$dataDir\clipbridge.log"
$action = New-ScheduledTaskAction -Execute $Exe `
    -Argument "connect $MacHost --key-file `"$keyFile`" --background --log `"$log`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
# Interactive logon type = runs in your desktop session, which is required for clipboard access.
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName "ClipBridge" -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "ClipBridge"
Write-Host "ClipBridge installed and started. Key: $keyFile  Log: $log"
