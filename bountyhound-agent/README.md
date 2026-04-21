# 🎯 BountyHound Agent

**Advanced Bug Bounty Hunting Framework with AI-Driven Testing**

[![Tests](https://img.shields.io/badge/tests-97%20passing-brightgreen)](https://github.com/yourusername/bountyhound-agent/actions)
[![Coverage](https://img.shields.io/badge/coverage-41%25-yellow)](https://github.com/yourusername/bountyhound-agent/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Security](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)

> ⚠️ **LEGAL WARNING**: This software is for **AUTHORIZED SECURITY TESTING ONLY**. Unauthorized computer access is illegal. See [TERMS_OF_USE.md](TERMS_OF_USE.md) and [SECURITY.md](SECURITY.md).

---

## 📋 Table of Contents

- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Testing Capabilities](#testing-capabilities)
- [Documentation](#documentation)
- [Legal & Ethics](#legal--ethics)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 About

BountyHound is a comprehensive security testing framework designed for authorized bug bounty hunting and security research. It combines Python-based testing engines with Claude Code AI orchestration to provide automated and semi-automated vulnerability discovery across multiple asset types.

### Scale
- **155 specialized agents** across 8 attack surfaces
- **12 skill categories** with 16 skill files
- **97 tests** with 43% code coverage
- **9 integrated tools** (mobile, cloud, blockchain, SAST, omnihack)
- **Database-driven** hunting prevents duplicate work

### Project Status

| Component | Status | Coverage | Notes |
|-----------|--------|----------|-------|
| **Web/API** | ✅ Complete | N/A | Claude-driven browser automation |
| **Mobile - Android** | ✅ Complete | 23% | APK analysis, Frida hooking, SSL bypass |
| **Mobile - iOS** | ⚠️ Partial | 48% | IPA analysis, string extraction (no runtime hooking) |
| **Cloud - AWS** | ✅ Complete | 36-68% | S3, IAM, SSRF with rate limiting |
| **Cloud - Azure/GCP** | ❌ Stub | 0% | Directory structure only |
| **Blockchain** | ✅ Wrapper | 0% | Slither/Mythril integration |
| **SAST - Secrets** | ✅ Complete | 79% | 25+ patterns, masked output |
| **SAST - Semgrep** | ⚠️ Partial | 15% | Wrapper only |
| **Desktop/Games** | ⚠️ Partial | 37% | Memory scanning, manual injection documented |
| **Hardware/IoT** | 🚧 Framework | 0% | Framework only - See [engine/hardware/README.md](engine/hardware/README.md) |

**Overall**: ~75% functional coverage (6 of 8 major asset types)

### Realistic ROI Expectations

**Disclaimer**: These are ESTIMATES based on typical bug bounty payouts, not guarantees.

- **Part-time (10-20 hrs/week)**: $20K-$100K/year
- **Full-time (40 hrs/week)**: $50K-$200K/year
- **Expert full-time (top 5%)**: $100K-$400K/year

**Reality Check**:
- Most findings pay $100-$2,000
- Critical findings are rare (1-5% of submissions)
- Duplicates are common (20-40% of findings)
- Results vary widely based on skill, target selection, and luck

---

## ✨ Features

### ✅ Working Features

- **Mobile Testing**
  - APK decompilation with jadx/apktool
  - Frida dynamic instrumentation
  - SSL pinning bypass (universal)
  - Root detection bypass
  - In-App Purchase bypass
  - IPA extraction and analysis
  - Binary string extraction
  - API endpoint discovery

- **Cloud Security**
  - S3 bucket enumeration (23 patterns)
  - IAM permission testing
  - SSRF payload generation
  - Rate limiting (1s default)
  - Exponential backoff
  - Proxy support (HTTP/HTTPS/SOCKS)

- **Blockchain**
  - Solidity static analysis (Slither wrapper)
  - Symbolic execution (Mythril wrapper)
  - Reentrancy detection
  - Access control verification

- **SAST**
  - Secrets scanning (25+ patterns: AWS, GitHub, Google, Stripe, etc.)
  - Secret masking in terminal output
  - Semgrep integration

- **Desktop/Games**
  - Memory pattern scanning
  - DLL injection (CreateRemoteThread)
  - Code cave detection

### ⚠️ Limitations

- **iOS**: No runtime hooking (requires jailbroken device)
- **Desktop**: Manual injection techniques documented but not implemented
- **Azure/GCP**: Stub implementations only
- **Hardware/IoT**: Not implemented

---

## 🚀 Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager
- (Optional) External tools for specific features

### Basic Installation

```bash
# Clone repository
git clone https://github.com/yourusername/bountyhound-agent.git
cd bountyhound-agent

# Install core dependencies
pip install -e .

# Install development dependencies
pip install -e ".[dev]"
```

### Feature-Specific Installation

```bash
# Mobile testing
pip install -e ".[mobile]"

# Cloud testing
pip install -e ".[cloud]"

# Blockchain testing
pip install -e ".[blockchain]"

# SAST scanning
pip install -e ".[sast]"

# Install all features
pip install -e ".[mobile,cloud,blockchain,sast]"
```

### External Tools (Optional)

Some features require external tools. See [docs/OPTIONAL-TOOLS.md](docs/OPTIONAL-TOOLS.md) for detailed installation guides.

```bash
# Mobile (Android) - RECOMMENDED
pip install -r requirements/requirements-mobile.txt

# Cloud (AWS CLI) - RECOMMENDED
pip install -r requirements/requirements-cloud.txt

# Blockchain (Slither, Mythril) - OPTIONAL
pip install -r requirements/requirements-blockchain.txt
pip install slither-analyzer mythril

# SAST (Semgrep) - OPTIONAL
pip install -r requirements/requirements-sast.txt
pip install semgrep

# Omnihack (Game hacking) - OPTIONAL
pip install -r requirements/requirements-omnihack.txt

# Hardware/IoT - IN DEVELOPMENT
pip install -r requirements/requirements-hardware.txt

# Development tools
pip install -r requirements/requirements-dev.txt
```

---

## 🏃 Quick Start

### 1. Mobile App Testing (Android)

```bash
# Analyze APK
python engine/mobile/android/apk_analyzer.py app.apk

# Hook live app with Frida
python engine/mobile/android/frida_hooker.py com.example.app --ssl --iap
```

### 2. Cloud Security (AWS)

```bash
# Enumerate S3 buckets
python engine/cloud/aws/s3_enumerator.py example.com --rate-limit 1.0

# Test IAM permissions
python engine/cloud/aws/iam_tester.py --rate-limit 1.0
```

### 3. Smart Contract Auditing

```bash
# Analyze Solidity contract
python engine/blockchain/solidity/contract_analyzer.py contract.sol
```

### 4. Secrets Scanning

```bash
# Scan repository for secrets
python engine/sast/analyzers/secrets_scanner.py /path/to/repo
```

### 5. Desktop Memory Scanning

```bash
# Scan process memory
python engine/omnihack/memory/scanner.py notepad.exe
```

---

## 🏗️ Architecture

BountyHound uses a hybrid architecture:

```
┌─────────────────────────────────────────────────────┐
│          Claude Code (AI Orchestration)             │
│  - Decision making                                  │
│  - Tool calling                                     │
│  - Workflow execution                               │
└─────────────┬───────────────────────────────────────┘
              │
              ├─► agents/ (Markdown workflows)
              ├─► skills/ (Knowledge base)
              └─► engine/ (Python tools)
                    ├─► mobile/      (APK, IPA analysis)
                    ├─► cloud/       (AWS, Azure, GCP)
                    ├─► blockchain/  (Solidity, Mythril)
                    ├─► sast/        (Secrets, Semgrep)
                    ├─► omnihack/    (Desktop, games)
                    └─► core/        (Shared utilities)
```

**Key Principle**: Claude provides the intelligence and orchestration, Python modules provide the tools.

---

## 🧪 Testing Capabilities

### Test Statistics

- **Total Tests**: 782 passing (97 unit/integration + 620 agent + 65 skill)
- **Coverage**: 43% core modules (agents/skills are markdown, not code)
- **Test Types**: Unit, Integration, Security, Documentation, Validation

### Run Tests

```bash
# All tests
pytest

# Unit tests only
pytest -m unit

# Skip slow tests
pytest -m "not slow"

# With coverage report
pytest --cov=engine --cov-report=html
```

---

## 📚 Documentation

- **[START-HERE.md](START-HERE.md)** - New user guide
- **[FULL-IMPLEMENTATION-SUMMARY.md](FULL-IMPLEMENTATION-SUMMARY.md)** - Complete implementation details
- **[SECURITY.md](SECURITY.md)** - Security policy and responsible disclosure
- **[TERMS_OF_USE.md](TERMS_OF_USE.md)** - Legal terms and disclaimers
- **[LICENSE](LICENSE)** - MIT License with legal disclaimer

### Agent Documentation

- [phased-hunter.md](agents/phased-hunter.md) - Main orchestrator
- [mobile/android-reverser.md](agents/mobile/android-reverser.md) - Android testing
- [mobile/ios-reverser.md](agents/mobile/ios-reverser.md) - iOS testing
- [cloud/aws-auditor.md](agents/cloud/aws-auditor.md) - AWS security
- [blockchain/solidity-auditor.md](agents/blockchain/solidity-auditor.md) - Smart contracts

---

## ⚖️ Legal & Ethics

### ⚠️ CRITICAL LEGAL WARNING

**Unauthorized computer access is illegal.** This software is for AUTHORIZED security testing only.

### Before Using BountyHound

✅ **You MUST**:
- Obtain explicit written authorization before testing ANY system
- Comply with bug bounty program rules and scope
- Follow all applicable laws (CFAA, Computer Misuse Act, etc.)
- Use responsible disclosure when reporting vulnerabilities
- Respect terms of service and acceptable use policies

❌ **You MUST NOT**:
- Test systems without explicit authorization
- Use this software for malicious purposes
- Violate terms of service or computer misuse laws
- Access, modify, or delete data without permission

### Legal Documents

Read these before using BountyHound:

1. **[LICENSE](LICENSE)** - MIT License with legal disclaimer
2. **[SECURITY.md](SECURITY.md)** - Security policy and compliance guidelines
3. **[TERMS_OF_USE.md](TERMS_OF_USE.md)** - Terms of use and liability limits

**By using this software, you agree to these terms and accept all liability. Authors assume $0 liability for misuse.**

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Read [SECURITY.md](SECURITY.md) for ethical guidelines
2. Follow the existing code style (Black, isort, flake8)
3. Add tests for new features
4. Update documentation
5. Submit a pull request

### Development Setup

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run linters
black engine/ tests/
isort engine/ tests/
flake8 engine/ tests/

# Run tests
pytest
```

---

## 📜 License

This project is licensed under the MIT License with an additional legal disclaimer - see [LICENSE](LICENSE) file for details.

**THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.**

---

## 🙏 Acknowledgments

- Built with [Claude Code](https://claude.ai/code)
- Inspired by the bug bounty and security research community
- Special thanks to responsible disclosure advocates

---

## 📞 Contact

- Security Issues: [See SECURITY.md](SECURITY.md)
- General Questions: [GitHub Issues](https://github.com/yourusername/bountyhound-agent/issues)
- Legal Questions: Consult a qualified attorney

---

**Remember: With great power comes great responsibility. Always get authorization before testing.**
