# BountyHound Installation Guide

## Quick Install

### From Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/bountyhound/bountyhound-agent.git
cd bountyhound-agent

# Install in development mode
pip install -e .

# Verify installation
bountyhound doctor
```

### From PyPI (Stable Release)

```bash
# Basic installation
pip install bountyhound

# With all optional features
pip install bountyhound[all]

# With specific features
pip install bountyhound[cloud]      # AWS testing
pip install bountyhound[mobile]     # Android/iOS analysis
pip install bountyhound[blockchain] # Smart contract testing
pip install bountyhound[sast]       # Static analysis tools
```

## Installation Options

### Core Installation (Minimal)

Installs only core dependencies:
- `requests` - HTTP client
- `colorama` - Terminal colors
- `python-dateutil` - Date handling

```bash
pip install bountyhound
```

### Feature-Specific Installations

**Cloud Testing (AWS)**
```bash
pip install bountyhound[cloud]
```
Adds: `boto3` for AWS IAM testing, S3 enumeration, metadata SSRF

**Mobile App Analysis**
```bash
pip install bountyhound[mobile]
```
Adds: `androguard` for Android APK security analysis

**Blockchain/Smart Contracts**
```bash
pip install bountyhound[blockchain]
```
Adds: `slither-analyzer`, `mythril` for Solidity analysis

**SAST (Static Analysis)**
```bash
pip install bountyhound[sast]
```
Adds: `semgrep` for comprehensive code scanning

**All Features**
```bash
pip install bountyhound[all]
```
Installs all optional dependencies (recommended)

## Development Installation

For contributing or modifying BountyHound:

```bash
# Clone repository
git clone https://github.com/bountyhound/bountyhound-agent.git
cd bountyhound-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[all]"
pip install -r requirements-dev.txt

# Run tests
pytest

# Check code coverage
pytest --cov=engine --cov=cli
```

## Post-Installation Setup

### 1. Verify Installation

```bash
bountyhound doctor
```

Expected output:
```
╔══════════════════════════════════════════════════════════════════╗
║                    BOUNTY HOUND v5.0.0                           ║
║              Autonomous Bug Bounty Hunting System                 ║
╠══════════════════════════════════════════════════════════════════╣
║  Database: Ready    │  Tools: 9 integrated  │  Mode: Database-First║
╚══════════════════════════════════════════════════════════════════╝

=== BountyHound Health Check ===

✓ Database: OK (0 targets)
✓ Python: 3.11.0
✓ requests: OK (HTTP client)
✓ colorama: OK (Terminal colors)
✓ boto3: OK (AWS testing (optional))

BountyHound is ready!
```

### 2. Initialize Database

The database is automatically initialized on first use at:
- **Linux/Mac**: `~/.bountyhound/bountyhound.db`
- **Windows**: `C:\Users\<username>\.bountyhound\bountyhound.db`

To check database status:
```bash
bountyhound db stats
```

### 3. Configure AWS Credentials (Optional)

For cloud testing features:

```bash
# Option 1: Environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret

# Option 2: AWS credentials file
aws configure

# Option 3: IAM role (if running on EC2/Lambda/ECS)
# No configuration needed
```

### 4. Test CLI Commands

```bash
# View database stats
bountyhound db stats

# Check for duplicates
bountyhound db check-duplicate example.com IDOR "api,users"

# View successful payloads
bountyhound db payloads --vuln-type XSS
```

## Troubleshooting

### ImportError: No module named 'engine'

**Cause**: BountyHound not installed or virtual environment not activated

**Solution**:
```bash
# Reinstall
pip install -e .

# Or activate virtual environment
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### Database permission errors

**Cause**: Insufficient permissions to create `~/.bountyhound/` directory

**Solution**:
```bash
# Create directory manually
mkdir -p ~/.bountyhound
chmod 755 ~/.bountyhound
```

### Missing optional dependencies

**Cause**: Feature-specific tools not installed

**Solution**:
```bash
# Install all features
pip install bountyhound[all]

# Or specific feature
pip install bountyhound[cloud]
```

### `bountyhound` command not found

**Cause**: Installation directory not in PATH

**Solution**:
```bash
# Find installation location
python -m pip show bountyhound

# Add to PATH (Linux/Mac)
export PATH="$PATH:$HOME/.local/bin"

# Or use python -m
python -m cli.main doctor
```

## Upgrading

### From pip

```bash
pip install --upgrade bountyhound[all]
```

### From source

```bash
cd bountyhound-agent
git pull
pip install -e ".[all]"
```

## Uninstallation

```bash
pip uninstall bountyhound
```

To remove database and configuration:
```bash
rm -rf ~/.bountyhound
```

## System Requirements

- **Python**: 3.8 or higher
- **OS**: Linux, macOS, Windows
- **Disk Space**: 100MB (minimal), 500MB (with all features)
- **RAM**: 512MB minimum, 2GB recommended

## Next Steps

- Read [CLAUDE.md](../CLAUDE.md) for database-first workflow
- Read [README.md](../README.md) for feature overview
- Run `bountyhound doctor` to verify setup
- Start hunting with `bountyhound db stats`
