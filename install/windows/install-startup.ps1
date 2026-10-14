# Registers ClipBridge to start hidden at logon and connect to your Mac.
#   .\install-startup.ps1 -MacHost my-mac -Key <passphrase> [-Exe C:\Tools\clipbridge.exe]
# Remove with:  Unregister-ScheduledTask -TaskName ClipBridge -Confirm:$false
param(
    [Parameter(Mandatory)] [string] $MacHost,
    [Parameter(Mandatory)] [string] $Key,
    [string] $Exe = "$env:LOCALAPPDATA\ClipBridge\clipbridge.exe"
)

if (-not (Test-Path $Exe)) {
    $dir = Split-Path $Exe
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $here = Join-Path $PSScriptRoot "clipbridge.exe"
    if (Test-Path $here) { Copy-Item $here $Exe } else { throw "clipbridge.exe not found at $Exe or next to this script" }
}

$log = "$env:LOCALAPPDATA\ClipBridge\clipbridge.log"
$action = New-ScheduledTaskAction -Execute $Exe -Argument "connect $MacHost --key $Key --background --log `"$log`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
# Interactive logon type = runs in your desktop session, which is required for clipboard access.
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName "ClipBridge" -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "ClipBridge"
Write-Host "ClipBridge installed and started. Log: $log"
