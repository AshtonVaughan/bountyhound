# OMNIHACK Tool Suite Test Script

$ErrorActionPreference = "Continue"

Write-Host "=" -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "OMNIHACK Tool Suite Test" -ForegroundColor Cyan
Write-Host "=" -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host ""

$tests = @()

# Test 1: Python
Write-Host "[*] Testing Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[+] $pythonVersion" -ForegroundColor Green
    $tests += @{name="Python"; status="PASS"}
} catch {
    Write-Host "[-] Python not found" -ForegroundColor Red
    $tests += @{name="Python"; status="FAIL"}
}

# Test 2: MinGW/GCC
Write-Host "`n[*] Testing MinGW (C++ compiler)..." -ForegroundColor Yellow
try {
    $gccVersion = gcc --version 2>&1 | Select-Object -First 1
    Write-Host "[+] $gccVersion" -ForegroundColor Green
    $tests += @{name="MinGW/GCC"; status="PASS"}
} catch {
    Write-Host "[-] GCC not found" -ForegroundColor Red
    $tests += @{name="MinGW/GCC"; status="FAIL"}
}

# Test 3: x64dbg
Write-Host "`n[*] Testing x64dbg..." -ForegroundColor Yellow
$x64dbgPath = "C:\Users\vaugh\Projects\bountyhound-agent\tools\x64dbg\release\x64\x64dbg.exe"
if (Test-Path $x64dbgPath) {
    Write-Host "[+] x64dbg found at: $x64dbgPath" -ForegroundColor Green
    $tests += @{name="x64dbg"; status="PASS"}
} else {
    Write-Host "[-] x64dbg not found" -ForegroundColor Red
    $tests += @{name="x64dbg"; status="FAIL"}
}

# Test 4: Cheat Engine
Write-Host "`n[*] Testing Cheat Engine..." -ForegroundColor Yellow
$cePath = "C:\Users\vaugh\Projects\bountyhound-agent\tools\CheatEngine.exe"
if (Test-Path $cePath) {
    Write-Host "[+] Cheat Engine installer found at: $cePath" -ForegroundColor Green
    $tests += @{name="Cheat Engine"; status="PASS"}
} else {
    Write-Host "[-] Cheat Engine not found" -ForegroundColor Red
    $tests += @{name="Cheat Engine"; status="FAIL"}
}

# Test 5: Ghidra
Write-Host "`n[*] Testing Ghidra..." -ForegroundColor Yellow
$ghidraPath = "C:\Users\vaugh\Projects\bountyhound-agent\tools\ghidra\ghidraRun.bat"
if (Test-Path $ghidraPath) {
    Write-Host "[+] Ghidra found at: $ghidraPath" -ForegroundColor Green
    $tests += @{name="Ghidra"; status="PASS"}
} else {
    Write-Host "[-] Ghidra not found" -ForegroundColor Red
    $tests += @{name="Ghidra"; status="FAIL"}
}

# Test 6: WinDbg
Write-Host "`n[*] Testing WinDbg..." -ForegroundColor Yellow
try {
    $windbgPath = Get-Command windbg -ErrorAction SilentlyContinue
    if ($windbgPath) {
        Write-Host "[+] WinDbg found at: $($windbgPath.Source)" -ForegroundColor Green
        $tests += @{name="WinDbg"; status="PASS"}
    } else {
        Write-Host "[-] WinDbg not found (install Windows SDK)" -ForegroundColor Yellow
        $tests += @{name="WinDbg"; status="OPTIONAL"}
    }
} catch {
    Write-Host "[-] WinDbg not found" -ForegroundColor Yellow
    $tests += @{name="WinDbg"; status="OPTIONAL"}
}

# Test 7: Python modules
Write-Host "`n[*] Testing Python modules..." -ForegroundColor Yellow
$modules = @("pymem", "psutil", "pefile", "capstone")
$moduleStatus = "PASS"

foreach ($module in $modules) {
    try {
        python -c "import $module; print('$module OK')" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] $module installed" -ForegroundColor Green
        } else {
            Write-Host "[-] $module not installed" -ForegroundColor Red
            $moduleStatus = "FAIL"
        }
    } catch {
        Write-Host "[-] $module not installed" -ForegroundColor Red
        $moduleStatus = "FAIL"
    }
}
$tests += @{name="Python Modules"; status=$moduleStatus}

# Test 8: Compiled C++ modules
Write-Host "`n[*] Testing compiled C++ modules..." -ForegroundColor Yellow
$injectPath = "C:\Users\vaugh\Projects\bountyhound-agent\engine\omnihack\injection\classic_inject.exe"
if (Test-Path $injectPath) {
    Write-Host "[+] classic_inject.exe found" -ForegroundColor Green
    $tests += @{name="C++ Modules"; status="PASS"}
} else {
    Write-Host "[-] classic_inject.exe not compiled" -ForegroundColor Yellow
    $tests += @{name="C++ Modules"; status="PENDING"}
}

# Test 9: Memory scanner
Write-Host "`n[*] Testing memory scanner module..." -ForegroundColor Yellow
try {
    $testResult = python -c "from engine.omnihack.memory import MemoryScanner; print('OK')" 2>&1
    if ($testResult -like "*OK*") {
        Write-Host "[+] Memory scanner module working!" -ForegroundColor Green
        $tests += @{name="Memory Scanner"; status="PASS"}
    } else {
        Write-Host "[-] Memory scanner import failed" -ForegroundColor Red
        $tests += @{name="Memory Scanner"; status="FAIL"}
    }
} catch {
    Write-Host "[-] Memory scanner import failed" -ForegroundColor Red
    $tests += @{name="Memory Scanner"; status="FAIL"}
}

# Summary
Write-Host "`n" -NoNewline
Write-Host "=" -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "=" -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host ""

$passed = ($tests | Where-Object { $_.status -eq "PASS" }).Count
$failed = ($tests | Where-Object { $_.status -eq "FAIL" }).Count
$optional = ($tests | Where-Object { $_.status -eq "OPTIONAL" -or $_.status -eq "PENDING" }).Count

foreach ($test in $tests) {
    $status = switch ($test.status) {
        "PASS" { "[+] PASS" }
        "FAIL" { "[-] FAIL" }
        "OPTIONAL" { "[~] OPTIONAL" }
        "PENDING" { "[~] PENDING" }
    }

    $color = switch ($test.status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        default { "Yellow" }
    }

    Write-Host ("{0,-25} {1}" -f $test.name, $status) -ForegroundColor $color
}

Write-Host "`nResults: $passed passed, $failed failed, $optional optional" -ForegroundColor Cyan

if ($failed -eq 0) {
    Write-Host "`n[+] All critical tests passed! Ready to hunt!" -ForegroundColor Green
} else {
    Write-Host "`n[!] Some tests failed. Run install-tools.ps1 again" -ForegroundColor Yellow
}

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
