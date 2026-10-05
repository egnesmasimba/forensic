$ErrorActionPreference = "Stop"

$ServiceName = "SystemUpdateSvc"
$DisplayName = "System Update Service"
$Description = "Provides system stability and updates"

$InstallDir = Join-Path $env:ProgramFiles "SystemUpdate"
$ExeName = "system-update.exe"
$ExePath = Join-Path $InstallDir $ExeName
$PyzName = "system-update.pyz"
$PyzPath = Join-Path $InstallDir $PyzName
$ConfigDir = Join-Path $env:ProgramData "SystemUpdate"
$ConfigFile = Join-Path $ConfigDir "config.json"
$LogDir = Join-Path $env:ProgramData "SystemUpdate\Logs"

$PythonExe = Join-Path $InstallDir "python\python.exe"

function Write-HostInfo($msg) {
    Write-Host "[*] $msg" -ForegroundColor Cyan
}

function Write-HostOK($msg) {
    Write-Host "[+] $msg" -ForegroundColor Green
}

function Write-HostErr($msg) {
    Write-Host "[!] $msg" -ForegroundColor Red
}

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-HostErr "This script must be run as Administrator"
    exit 1
}

Write-HostInfo "Installing $DisplayName..."

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Write-HostOK "Created directories"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourcePyz = Join-Path $ScriptDir "..\..\packages\system-update-windows-x86_64.pyz"
if (Test-Path $SourcePyz) {
    Copy-Item -Force $SourcePyz $PyzPath
    Write-HostOK "Copied pyz bundle to $PyzPath"
}

if (Test-Path (Join-Path $ScriptDir "python-embed")) {
    Copy-Item -Recurse -Force (Join-Path $ScriptDir "python-embed") (Join-Path $InstallDir "python")
    Write-HostOK "Copied embedded Python runtime"
}

$WrappedExe = Join-Path $ScriptDir "system-update.exe"
if (Test-Path $WrappedExe) {
    Copy-Item -Force $WrappedExe $ExePath
    Write-HostOK "Copied native wrapper executable"
}

$WrapperSource = Join-Path $InstallDir "run.vbs"
$VbsContent = @"
Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
Dim pythonCmd, pyzPath, configPath

pythonCmd = "$InstallDir\python\pythonw.exe"
pyzPath = "$PyzPath"
configPath = "$ConfigFile"

If Not fso.FileExists(pythonCmd) Then
    pythonCmd = "pythonw"
End If

WshShell.CurrentDirectory = "$InstallDir"
WshShell.Run Chr(34) & pythonCmd & Chr(34) & " " & Chr(34) & pyzPath & Chr(34) & " --config " & Chr(34) & configPath & Chr(34), 0, False
"@
Set-Content -Path $WrapperSource -Value $VbsContent -Encoding ASCII

$BatSource = Join-Path $InstallDir "svc_run.bat"
$BatContent = @"
@echo off
cd /d "$InstallDir"
if exist "$PythonExe" (
    "$PythonExe" "$PyzPath" --config "$ConfigFile"
) else (
    pythonw "$PyzPath" --config "$ConfigFile"
)
"@
Set-Content -Path $BatSource -Value $BatContent -Encoding ASCII

$SvcHostPath = Join-Path $InstallDir "svchost.exe"
$NssmPath = Join-Path $ScriptDir "nssm.exe"
$UseSc = $true

if (Test-Path $NssmPath) {
    $UseSc = $false
    Copy-Item $NssmPath (Join-Path $InstallDir "nssm.exe")
}

if ($UseSc) {
    $BinPath = "`"$env:SystemRoot\System32\cmd.exe`" /c `"$BatSource`""
    & sc.exe create $ServiceName binPath= $BinPath start= auto DisplayName= $DisplayName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-HostErr "sc.exe create failed, using srvany fallback"
        $UseSc = $false
    }
}

if (-not $UseSc) {
    $BinPath = "`"$env:SystemRoot\System32\srvany.exe`""
    & sc.exe create $ServiceName binPath= $BinPath start= auto DisplayName= $DisplayName 2>&1 | Out-Null
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters"
    New-Item -Path $RegPath -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name "Application" -Value "`"$env:SystemRoot\System32\cmd.exe`"" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name "AppParameters" -Value "/c `"$BatSource`"" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name "AppDirectory" -Value $InstallDir -PropertyType String -Force | Out-Null
}

& sc.exe description $ServiceName $Description 2>&1 | Out-Null
Write-HostOK "Registered service $ServiceName"

& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1 | Out-Null
& sc.exe failureflag $ServiceName 1 2>&1 | Out-Null
Write-HostOK "Configured failure recovery (restart on crash)"

$DefaultConfig = @{
    server_url = "https://update.example.com"
    tenant_id = "default"
    machine_id = [guid]::NewGuid().ToString()
    log_level = "INFO"
    log_file = Join-Path $LogDir "agent.log"
    check_interval_sec = 3600
    self_monitor_exclude = @(
        $ServiceName,
        "cmd.exe",
        "python.exe",
        "pythonw.exe",
        "srvany.exe",
        "svchost.exe",
        "nssm.exe"
    )
    # Transport security. Point ca_bundle at the server's CA certificate, and
    # set client_cert/client_key when the server requires mutual TLS. The agent
    # refuses plain HTTP and refuses to disable verification for a remote host.
    tls = @{
        verify_tls = $true
        ca_bundle = $null
        client_cert = $null
        client_key = $null
        allow_insecure_http = $false
        proxy = $null
    }
}
if (-not (Test-Path $ConfigFile)) {
    $DefaultConfig | ConvertTo-Json -Depth 4 | Set-Content -Path $ConfigFile -Encoding UTF8
    Write-HostOK "Wrote default config to $ConfigFile"
} else {
    Write-HostInfo "Config already exists at $ConfigFile - preserving"
}

icacls $ConfigDir /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /grant "Users:(OI)(CI)RX" /T /C 2>&1 | Out-Null
icacls $InstallDir /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /grant "Users:(OI)(CI)RX" /T /C 2>&1 | Out-Null
Write-HostOK "Hardened file permissions"

& sc.exe config $ServiceName obj= "LocalSystem" 2>&1 | Out-Null

& net.exe start $ServiceName 2>&1 | Out-Null
$StartResult = $LASTEXITCODE
if ($StartResult -eq 0 -or $StartResult -eq 2182) {
    Write-HostOK "Service $ServiceName started"
} else {
    Write-HostInfo "Service start returned $StartResult, querying status..."
    & sc.exe query $ServiceName
}

Write-Host ""
Write-HostOK "========================================"
Write-HostOK "Installation complete"
Write-HostOK "Service:       $ServiceName"
Write-HostOK "Display:       $DisplayName"
Write-HostOK "Install dir:   $InstallDir"
Write-HostOK "Config dir:    $ConfigDir"
Write-HostOK "Log dir:       $LogDir"
Write-HostOK "Config file:   $ConfigFile"
Write-HostOK "========================================"
Write-Host ""
Write-HostInfo "Admin commands:"
Write-HostInfo "  sc.exe query $ServiceName"
Write-HostInfo "  net.exe start $ServiceName"
Write-HostInfo "  net.exe stop  $ServiceName"
Write-HostInfo "  sc.exe delete $ServiceName   (uninstall)"
