# OMNIHACK Tool Suite Installation Script
# Run as Administrator

$ErrorActionPreference = "Stop"
$ToolsDir = "C:\Users\vaugh\Projects\bountyhound-agent\tools"

Write-Host "=" -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "OMNIHACK Tool Suite Installation" -ForegroundColor Cyan
Write-Host "=" -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host ""

# Create tools directory
New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

# Check for admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Not running as Administrator. Some features may not work." -ForegroundColor Yellow
}

# 1. Install Chocolatey (package manager)
Write-Host "`n[*] Installing Chocolatey..." -ForegroundColor Green
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Write-Host "[+] Chocolatey installed!" -ForegroundColor Green
} else {
    Write-Host "[+] Chocolatey already installed" -ForegroundColor Green
}

# 2. Install MinGW (C++ Compiler)
Write-Host "`n[*] Installing MinGW (C++ compiler)..." -ForegroundColor Green
if (!(Get-Command gcc -ErrorAction SilentlyContinue)) {
    choco install mingw -y
    Write-Host "[+] MinGW installed!" -ForegroundColor Green
    # Add to PATH
    $env:Path += ";C:\ProgramData\chocolatey\lib\mingw\tools\install\mingw64\bin"
} else {
    Write-Host "[+] MinGW already installed" -ForegroundColor Green
}

# 3. Download x64dbg
Write-Host "`n[*] Downloading x64dbg..." -ForegroundColor Green
$x64dbgPath = "$ToolsDir\x64dbg"
if (!(Test-Path "$x64dbgPath\release\x64\x64dbg.exe")) {
    $x64dbgUrl = "https://github.com/x64dbg/x64dbg/releases/latest/download/snapshot_2024-01-01_12-00.zip"
    $x64dbgZip = "$ToolsDir\x64dbg.zip"

    # Try to get latest release URL
    try {
        $latestRelease = Invoke-RestMethod "https://api.github.com/repos/x64dbg/x64dbg/releases/latest"
        $x64dbgUrl = ($latestRelease.assets | Where-Object { $_.name -like "snapshot*.zip" } | Select-Object -First 1).browser_download_url
    } catch {
        Write-Host "[!] Using fallback URL for x64dbg" -ForegroundColor Yellow
    }

    Invoke-WebRequest -Uri $x64dbgUrl -OutFile $x64dbgZip -UseBasicParsing
    Expand-Archive -Path $x64dbgZip -DestinationPath $x64dbgPath -Force
    Remove-Item $x64dbgZip
    Write-Host "[+] x64dbg installed at: $x64dbgPath" -ForegroundColor Green
} else {
    Write-Host "[+] x64dbg already installed" -ForegroundColor Green
}

# 4. Download Cheat Engine
Write-Host "`n[*] Downloading Cheat Engine..." -ForegroundColor Green
$ceUrl = "https://github.com/cheat-engine/cheat-engine/releases/download/7.5/CheatEngine75.exe"
$cePath = "$ToolsDir\CheatEngine.exe"
if (!(Test-Path $cePath)) {
    Invoke-WebRequest -Uri $ceUrl -OutFile $cePath -UseBasicParsing
    Write-Host "[+] Cheat Engine downloaded to: $cePath" -ForegroundColor Green
    Write-Host "[!] Run CheatEngine.exe to install (manual step)" -ForegroundColor Yellow
} else {
    Write-Host "[+] Cheat Engine already downloaded" -ForegroundColor Green
}

# 5. Download Ghidra
Write-Host "`n[*] Downloading Ghidra..." -ForegroundColor Green
$ghidraPath = "$ToolsDir\ghidra"
if (!(Test-Path "$ghidraPath\ghidraRun.bat")) {
    $ghidraUrl = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip"
    $ghidraZip = "$ToolsDir\ghidra.zip"

    Write-Host "[*] Downloading Ghidra (this may take a while, ~400MB)..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $ghidraUrl -OutFile $ghidraZip -UseBasicParsing
    Expand-Archive -Path $ghidraZip -DestinationPath $ToolsDir -Force

    # Find the extracted directory (it has version in name)
    $extractedDir = Get-ChildItem -Path $ToolsDir -Directory | Where-Object { $_.Name -like "ghidra*" } | Select-Object -First 1
    if ($extractedDir) {
        Move-Item -Path $extractedDir.FullName -Destination $ghidraPath -Force
    }

    Remove-Item $ghidraZip
    Write-Host "[+] Ghidra installed at: $ghidraPath" -ForegroundColor Green
    Write-Host "[!] Ghidra requires Java JDK 17+ to run" -ForegroundColor Yellow
} else {
    Write-Host "[+] Ghidra already installed" -ForegroundColor Green
}

# 6. Install Python packages
Write-Host "`n[*] Installing Python packages..." -ForegroundColor Green
$requirementsPath = "C:\Users\vaugh\Projects\bountyhound-agent\requirements-omnihack.txt"
if (Test-Path $requirementsPath) {
    python -m pip install --upgrade pip
    python -m pip install -r $requirementsPath
    Write-Host "[+] Python packages installed!" -ForegroundColor Green
} else {
    Write-Host "[!] requirements-omnihack.txt not found" -ForegroundColor Yellow
}

# 7. Install WinDbg (Windows SDK)
Write-Host "`n[*] WinDbg (Windows SDK) installation..." -ForegroundColor Green
if (!(Get-Command windbg -ErrorAction SilentlyContinue)) {
    Write-Host "[!] WinDbg requires Windows SDK installation" -ForegroundColor Yellow
    Write-Host "[*] Opening Windows SDK download page..." -ForegroundColor Yellow
    Start-Process "https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/"
    Write-Host "[!] Please install Windows SDK manually (select Debugging Tools)" -ForegroundColor Yellow
} else {
    Write-Host "[+] WinDbg already installed" -ForegroundColor Green
}

# 8. Compile C++ modules
Write-Host "`n[*] Compiling C++ injection modules..." -ForegroundColor Green
$injectionDir = "C:\Users\vaugh\Projects\bountyhound-agent\engine\omnihack\injection"
if (Test-Path "$injectionDir\classic_inject.cpp") {
    try {
        Set-Location $injectionDir
        g++ -o classic_inject.exe classic_inject.cpp -lkernel32 -luser32 -static-libgcc -static-libstdc++
        if (Test-Path "classic_inject.exe") {
            Write-Host "[+] classic_inject.exe compiled successfully!" -ForegroundColor Green
        }
    } catch {
        Write-Host "[!] Failed to compile: $_" -ForegroundColor Red
    }
} else {
    Write-Host "[!] classic_inject.cpp not found" -ForegroundColor Yellow
}

Write-Host "`n" -NoNewline
Write-Host "=" -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "=" -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 59) -ForegroundColor Cyan

Write-Host "`nTools installed at: $ToolsDir" -ForegroundColor Cyan
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Install Cheat Engine: $ToolsDir\CheatEngine.exe" -ForegroundColor White
Write-Host "2. Install Windows SDK for WinDbg (if needed)" -ForegroundColor White
Write-Host "3. Test tools: .\setup\test-tools.ps1" -ForegroundColor White
Write-Host "4. Start hunting: python -m omnihack.test" -ForegroundColor White

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
