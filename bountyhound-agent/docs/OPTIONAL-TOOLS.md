# Optional Tools Installation Guide

This guide covers the installation of optional external tools for BountyHound. These tools are **not required** for core functionality but enable specific features.

---

## 📦 Tool Categories

| Category | Tools | Status | Features Enabled |
|----------|-------|--------|------------------|
| **Blockchain** | slither-analyzer, mythril | ⚠️ Optional | Smart contract analysis |
| **SAST** | semgrep | ⚠️ Optional | Multi-language static analysis |
| **Mobile** | frida, frida-tools | ✅ Recommended | Dynamic instrumentation |
| **Omnihack** | Various | ⚠️ Optional | Game/desktop hacking |

---

## 🔗 Blockchain Tools

### slither-analyzer

**Purpose**: Solidity smart contract static analysis

**Installation**:
```bash
# Via pip
pip install slither-analyzer

# Via pipx (recommended - isolated environment)
pipx install slither-analyzer

# Verify installation
slither --version
```

**Alternative**: Use Docker
```bash
docker pull trailofbits/eth-security-toolbox
docker run -it -v $(pwd):/contracts trailofbits/eth-security-toolbox
```

**Features**:
- Detects 70+ vulnerability patterns
- Reentrancy detection
- Access control verification
- Gas optimization suggestions

**Documentation**: https://github.com/crytic/slither

---

### mythril

**Purpose**: Symbolic execution and security analysis for Ethereum smart contracts

**Installation**:
```bash
# Via pip
pip install mythril

# Verify installation
myth version
```

**Alternative**: Use Docker
```bash
docker pull mythril/myth
docker run mythril/myth analyze <contract>
```

**Features**:
- Symbolic execution
- Concolic analysis
- Vulnerability detection (reentrancy, integer overflow, etc.)

**Documentation**: https://github.com/ConsenSys/mythril

**Note**: Mythril requires a significant amount of computational resources and may be slow on large contracts.

---

## 🔍 SAST Tools

### semgrep

**Purpose**: Multi-language static analysis for security vulnerabilities

**Installation**:
```bash
# Via pip
pip install semgrep

# Via Homebrew (macOS/Linux)
brew install semgrep

# Verify installation
semgrep --version
```

**Features**:
- Support for 30+ languages
- Custom rule creation
- Fast pattern matching
- Open-source rules from Semgrep Registry

**Usage with BountyHound**:
```bash
# Scan a codebase
python engine/sast/analyzers/semgrep_runner.py /path/to/code

# Or use directly
semgrep --config=auto /path/to/code
```

**Documentation**: https://semgrep.dev/docs/

**Registry**: https://semgrep.dev/r

---

## 📱 Mobile Tools (Recommended)

### frida & frida-tools

**Purpose**: Dynamic instrumentation for runtime hooking and manipulation

**Installation**:
```bash
# Install Frida
pip install frida frida-tools

# Verify installation
frida --version
```

**Additional Setup**:
```bash
# For Android (requires rooted device or emulator)
# 1. Download frida-server for your device architecture
wget https://github.com/frida/frida/releases/download/<version>/frida-server-<version>-android-<arch>.xz

# 2. Extract and push to device
unxz frida-server-*.xz
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"

# 3. Run frida-server on device
adb shell "/data/local/tmp/frida-server &"
```

**Features**:
- SSL pinning bypass
- Root detection bypass
- In-App Purchase bypass
- API call interception
- Memory manipulation

**Documentation**: https://frida.re/docs/

---

## 🎮 Omnihack Tools (Optional)

### Cheat Engine

**Purpose**: Memory scanning and game hacking

**Installation**:
- **Windows**: Download from https://www.cheatengine.org/
- **Linux**: Available via Wine or native build

**Features**:
- Memory scanning
- Pointer scanning
- Debugger
- Disassembler

**Note**: For educational and authorized testing only.

---

### x64dbg / x86dbg

**Purpose**: Windows debugger for reverse engineering

**Installation**:
- Download from https://x64dbg.com/
- Extract and run (portable)

**Features**:
- Debugging x86/x64 applications
- Plugin support
- Scripting capabilities

---

### Ghidra

**Purpose**: NSA's software reverse engineering framework

**Installation**:
```bash
# Download from https://ghidra-sre.org/
# Requires Java JDK 11+

# Extract and run
unzip ghidra_*.zip
cd ghidra_*
./ghidraRun
```

**Features**:
- Decompiler for multiple architectures
- Scripting with Python/Java
- Collaborative reverse engineering

**Documentation**: https://ghidra-sre.org/

---

## 🔧 Hardware/IoT Tools (Future)

**Note**: Hardware testing is in early development. The following tools are planned for future integration:

- **binwalk** - Firmware extraction and analysis
- **firmwalker** - Firmware security scanner
- **JTAG tools** - Hardware debugging
- **RF analyzers** - Radio frequency analysis

**Current Status**: Framework only, no active implementation

---

## 📋 Installation Summary

### Quick Install (Recommended Tools)

```bash
# Core + Recommended
pip install -e ".[mobile,cloud,sast]"

# Add Frida for mobile testing
pip install frida frida-tools

# Add Semgrep for SAST
pip install semgrep
```

### Full Install (All Optional Tools)

```bash
# Install all Python dependencies
pip install -e ".[mobile,cloud,blockchain,sast,dev]"

# Install blockchain tools
pip install slither-analyzer mythril

# Install SAST tools
pip install semgrep bandit

# Install omnihack tools
pip install -r requirements/requirements-omnihack.txt
```

### Selective Install

```bash
# Just blockchain
pip install -e ".[blockchain]"
pip install slither-analyzer mythril

# Just SAST
pip install -e ".[sast]"
pip install semgrep

# Just mobile
pip install -e ".[mobile]"
pip install frida frida-tools
```

---

## ⚠️ Important Notes

### System Requirements

- **Blockchain tools** require significant disk space (>2GB for dependencies)
- **Mythril** requires substantial RAM (>4GB recommended)
- **Frida** requires:
  - Rooted Android device or emulator
  - Jailbroken iOS device (for iOS testing)
- **Omnihack tools** mostly Windows-only

### Permissions

Most tools require **authorized testing only**:
- Only use on systems you own or have explicit permission to test
- Bug bounty programs typically do NOT allow:
  - Network flooding
  - DoS attacks
  - Social engineering
- Check program scope before testing

### Troubleshooting

**Slither installation fails**:
- Try using `pipx` for isolated installation
- Check Python version (requires 3.8+)
- Use Docker image as alternative

**Mythril installation fails**:
- Requires z3-solver which can be problematic
- Try: `pip install z3-solver` first
- Use Docker image as alternative

**Semgrep slow on large codebases**:
- Use `--metrics=off` flag
- Scan specific directories only
- Use `.semgrepignore` to exclude files

**Frida connection issues**:
- Ensure frida-server version matches frida-tools
- Check device is rooted/jailbroken
- Verify adb connection: `adb devices`

---

## 📚 Additional Resources

- **BountyHound Docs**: [README.md](../README.md)
- **Security Policy**: [SECURITY.md](../SECURITY.md)
- **Terms of Use**: [TERMS_OF_USE.md](../TERMS_OF_USE.md)

---

---

## 🔍 Web Security Tools (Integrated v5.1)

These 10 tools are now fully integrated into BountyHound with automatic fallbacks.
Run `bountyhound doctor` to see which are installed.

| Tool | Agent File | Purpose |
|------|-----------|---------|
| ffuf | `engine/agents/ffuf_fuzzer.py` | Directory, parameter, and vhost fuzzing |
| katana | `engine/agents/katana_crawler.py` | Fast web crawler with JS parsing |
| gau | `engine/agents/gau_urls.py` | Historical URL gathering (Wayback, CommonCrawl, OTX) |
| interactsh-client | `engine/agents/interactsh_oast.py` | OOB interaction server for blind vulns |
| arjun | `engine/agents/arjun_params.py` | Hidden HTTP parameter discovery |
| dalfox | `engine/agents/dalfox_xss.py` | Context-aware XSS scanner |
| dnsx | `engine/agents/dnsx_resolver.py` | DNS resolution and takeover detection |
| feroxbuster | `engine/agents/feroxbuster_discovery.py` | Recursive content discovery |
| trufflehog | `engine/agents/trufflehog_secrets.py` | Secret scanning in JS/git repos |
| sqlmap | `engine/agents/sqlmap_injection.py` | SQL injection detection |

---

### ffuf

**Purpose**: Fast web fuzzer for directories, parameters, and virtual hosts

**Installation**:
```bash
# Via Go
go install github.com/ffuf/ffuf/v2@latest

# Via apt
sudo apt install ffuf

# Verify
ffuf -V
```

**Wordlists (recommended)**:
```bash
# SecLists (essential)
sudo apt install seclists
# Or: git clone https://github.com/danielmiessler/SecLists /opt/seclists
```

---

### katana

**Purpose**: Fast web crawler with JavaScript parsing and API endpoint discovery

**Installation**:
```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Verify
katana -version
```

---

### gau (GetAllURLs)

**Purpose**: Fetches known URLs from Wayback Machine, CommonCrawl, OTX, and URLScan simultaneously

**Installation**:
```bash
go install github.com/lc/gau/v2/cmd/gau@latest

# Verify
gau --version
```

---

### interactsh-client

**Purpose**: Out-of-band interaction server for detecting blind SSRF, blind XSS, XXE, and DNS callbacks

**Installation**:
```bash
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Alternative: use web UI
# https://app.interactsh.com

# Verify
interactsh-client -version
```

---

### arjun

**Purpose**: HTTP parameter discovery - finds hidden GET/POST parameters

**Installation**:
```bash
pip install arjun

# Verify
arjun --help
```

---

### dalfox

**Purpose**: Context-aware XSS scanner with blind XSS callback support

**Installation**:
```bash
go install github.com/hahwul/dalfox/v2@latest

# Verify
dalfox version
```

---

### dnsx

**Purpose**: Fast DNS toolkit for bulk resolution, brute-forcing, and takeover fingerprinting

**Installation**:
```bash
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Verify
dnsx -version
```

---

### feroxbuster

**Purpose**: Recursive content and directory discovery with auto-tune

**Installation**:
```bash
# Windows (via Cargo)
cargo install feroxbuster

# Linux
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# Via apt
sudo apt install feroxbuster

# Verify
feroxbuster --version
```

---

### trufflehog

**Purpose**: Scans git repositories and files for leaked secrets (API keys, tokens, credentials)

**Installation**:
```bash
# Via brew
brew install trufflesecurity/trufflehog/trufflehog

# Via curl (Linux/Mac)
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Windows: download from https://github.com/trufflesecurity/trufflehog/releases

# Verify
trufflehog --version
```

---

### sqlmap

**Purpose**: SQL injection detection and exploitation

**Installation**:
```bash
# Via pip
pip install sqlmap

# Via apt
sudo apt install sqlmap

# Via git
git clone https://github.com/sqlmapproject/sqlmap.git

# Verify
sqlmap --version
```

---

### Install All Go Tools at Once

```bash
go install github.com/ffuf/ffuf/v2@latest && \
go install github.com/projectdiscovery/katana/cmd/katana@latest && \
go install github.com/lc/gau/v2/cmd/gau@latest && \
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
go install github.com/hahwul/dalfox/v2@latest && \
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

pip install arjun sqlmap
```

---

**Last Updated**: 2026-02-20
**Maintained By**: BountyHound Team
