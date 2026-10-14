# Sets up ClipBridge on Windows: pairs with your Mac (if not done yet) and registers
# a logon task that runs hidden and keeps reconnecting.
#   .\install-startup.ps1 -MacHost brians-mbp.local [-Pair] [-Exe C:\Tools\clipbridge.exe]
# Before running it, start `clipbridge listen` on the Mac so it shows a pairing code.
# -Pair pairs again even if a key is already stored (e.g. after re-pairing the Mac).
# Running it again with a newer clipbridge.exe next to the script upgrades the install.
# Remove with:  Unregister-ScheduledTask -TaskName ClipBridge -Confirm:$false
param(
    [Parameter(Mandatory)] [string] $MacHost,
    [switch] $Pair,
    [string] $Exe = "$env:LOCALAPPDATA\ClipBridge\clipbridge.exe"
)

$ErrorActionPreference = "Stop"

$dataDir = "$env:LOCALAPPDATA\ClipBridge"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

# Stop a running copy so the exe can be replaced and the task re-registered cleanly.
if (Get-ScheduledTask -TaskName ClipBridge -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName ClipBridge }
Get-Process clipbridge -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

$here = Join-Path $PSScriptRoot "clipbridge.exe"
if (Test-Path $here) {
    New-Item -ItemType Directory -Force -Path (Split-Path $Exe) | Out-Null
    Copy-Item $here $Exe -Force
} elseif (-not (Test-Path $Exe)) {
    throw "clipbridge.exe not found at $Exe or next to this script"
}

# Pairing saves the key to key.txt in the data folder, readable only by you and SYSTEM.
$keyFile = Join-Path $dataDir "key.txt"
if ($Pair -or -not (Test-Path $keyFile)) {
    Write-Host 'Not paired yet. On the Mac, run "clipbridge listen" and read the pairing code it shows.'
    & $Exe pair $MacHost
    if ($LASTEXITCODE -ne 0) { throw "pairing failed; run the script again once the Mac shows a code" }
}

$log = "$dataDir\clipbridge.log"
$action = New-ScheduledTaskAction -Execute $Exe `
    -Argument "connect $MacHost --background --log `"$log`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
# Interactive logon type = runs in your desktop session, which is required for clipboard access.
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName "ClipBridge" -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "ClipBridge"
Write-Host "ClipBridge installed and started. Log: $log"
