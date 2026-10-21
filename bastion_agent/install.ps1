# bastion agent installer — Windows (PowerShell 5+). No admin, no downloads.
#   powershell -ExecutionPolicy Bypass -File install.ps1 dist\bastion-agent-0.1.0.pyz
# Puts bastion-agent.cmd in %LOCALAPPDATA%\bastion-agent and runs the preflight.
param([Parameter(Mandatory = $true)][string]$Pyz)
$ErrorActionPreference = "Stop"
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { Write-Error "Python 3.8+ is required (python.org or the Store); none on PATH"; exit 1 }
& $py.Source -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"
if ($LASTEXITCODE -ne 0) { Write-Error "Python is older than 3.8"; exit 1 }
if (Test-Path "$Pyz.sha256") {
    $want = (Get-Content "$Pyz.sha256").Split(" ")[0].ToLower()
    $have = (Get-FileHash -Algorithm SHA256 $Pyz).Hash.ToLower()
    if ($want -ne $have) { Write-Error "checksum MISMATCH - refusing to install"; exit 1 }
    Write-Host "checksum ok"
}
$dir = Join-Path $env:LOCALAPPDATA "bastion-agent"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Copy-Item $Pyz (Join-Path $dir "bastion-agent.pyz") -Force
$cmd = Join-Path $dir "bastion-agent.cmd"
"@echo off`r`n`"$($py.Source)`" `"$dir\bastion-agent.pyz`" %*`r`n" | Set-Content -Path $cmd -Encoding ASCII
Write-Host "installed $cmd"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
    Write-Host "added $dir to your user PATH (open a new terminal)"
}
& $cmd --version
& $cmd doctor
Write-Host ""
Write-Host "next: put your manifest at %APPDATA%\bastion-agent\manifest.yaml, set FREEAGENT_OWNER_RECIPIENT"
Write-Host "      (age-keygen), then: bastion-agent sweep %APPDATA%\bastion-agent\manifest.yaml --once"
