# Sets up ClipBridge on Windows: pairs with each Mac that isn't paired yet and registers
# a logon task that runs hidden and keeps reconnecting to all of them.
#   .\install-startup.ps1 -MacHost brians-mbp.local [-Pair] [-Exe C:\Tools\clipbridge.exe]
#   .\install-startup.ps1 -MacHost 192.168.1.20, 192.168.1.31        (two Macs)
# Before running it, start `clipbridge listen` on any Mac not paired yet so it shows a code.
# With several Macs, a copy on any machine reaches all the others.
# -Pair pairs again with every listed Mac even if keys are stored.
# Running it again with a newer clipbridge.exe next to the script upgrades the install.
# Remove with:  Unregister-ScheduledTask -TaskName ClipBridge -Confirm:$false
param(
    [Parameter(Mandatory)] [string[]] $MacHost,
    [switch] $Pair,
    [string] $Exe = "$env:LOCALAPPDATA\ClipBridge\clipbridge.exe"
)

$ErrorActionPreference = "Stop"

$dataDir = "$env:LOCALAPPDATA\ClipBridge"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

# Note which Mac(s) the current task connects to, before replacing it.
$oldHosts = @()
$oldTask = Get-ScheduledTask -TaskName ClipBridge -ErrorAction SilentlyContinue
if ($oldTask) {
    $tokens = @($oldTask.Actions[0].Arguments -split '\s+' | Where-Object { $_ })
    if ($tokens.Count -gt 1 -and $tokens[0] -eq 'connect') {
        foreach ($t in $tokens[1..($tokens.Count - 1)]) {
            if ($t.StartsWith('--')) { break }
            $oldHosts += $t
        }
    }
}

# Stop a running copy so the exe can be replaced and the task re-registered cleanly.
if ($oldTask) { Stop-ScheduledTask -TaskName ClipBridge }
Get-Process clipbridge -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

$here = Join-Path $PSScriptRoot "clipbridge.exe"
if (Test-Path $here) {
    New-Item -ItemType Directory -Force -Path (Split-Path $Exe) | Out-Null
    Copy-Item $here $Exe -Force
} elseif (-not (Test-Path $Exe)) {
    throw "clipbridge.exe not found at $Exe or next to this script"
}

# Versions before 0.4 kept a single key in key.txt. Hand it to the Mac it belongs to
# (the one the old task connected to), so adding a second Mac keeps the first pairing.
$legacyKey = Join-Path $dataDir "key.txt"
if (-not $Pair -and (Test-Path $legacyKey) -and $oldHosts.Count -eq 1 -and ($MacHost -contains $oldHosts[0])) {
    & $Exe pair $oldHosts[0]
    if ($LASTEXITCODE -ne 0) { Write-Warning "couldn't move the existing key for $($oldHosts[0]); you may be asked to pair it again" }
}

# Pair each Mac that has no key yet (all of them with -Pair). Keys are saved in the
# keys folder under the data folder, readable only by you and SYSTEM.
Write-Host 'If a Mac is not paired yet, run "clipbridge listen" on it and enter the code it shows when asked.'
$pairArgs = @('pair') + $MacHost
if ($Pair) { $pairArgs += '--force' }
& $Exe @pairArgs
if ($LASTEXITCODE -ne 0) { throw "pairing failed; run the script again once each unpaired Mac shows a code" }

$log = "$dataDir\clipbridge.log"
$action = New-ScheduledTaskAction -Execute $Exe `
    -Argument "connect $($MacHost -join ' ') --background --log `"$log`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
# Interactive logon type = runs in your desktop session, which is required for clipboard access.
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName "ClipBridge" -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "ClipBridge"
Write-Host "ClipBridge installed and started for $($MacHost -join ', '). Log: $log"
