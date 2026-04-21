# Agent Profile Management

**Smart agent loading system to optimize Claude Code performance**

## The Problem

BountyHound has **155 specialized agents** for different attack surfaces. Loading all of them simultaneously:
- Uses **16.4k context tokens** (exceeds 15k recommended limit)
- Slows down Claude Code performance
- Wastes context on agents you don't need

## The Solution

**Agent Profiles** - Group agents by attack surface and load only what's needed:

| Profile | Agents | Use Case |
|---------|--------|----------|
| **core** | 6 | Always active (phased-hunter, discovery-engine, etc.) |
| **web** | 27 | Web application testing (XSS, SQLi, CSRF, etc.) |
| **api** | 10 | REST/GraphQL/gRPC testing |
| **blockchain** | 2 | Web3/crypto targets |
| **mobile** | 3 | iOS/Android apps |
| **cloud** | 8 | AWS/GCP/Azure infrastructure |
| **infrastructure** | 7 | Network, DNS, CDN testing |
| **advanced** | 11 | Request smuggling, cache poisoning, WAF bypass |
| **recon** | 6 | OSINT, subdomain enumeration |
| **specialized** | 8 | IoT, firmware, game hacking |
| **cicd** | 2 | CI/CD pipeline security |

**Default enabled**: core + web + api = **43 agents** (~3-4k tokens)

## Usage

### Manual Management

```bash
# Show current status
/agents status

# List all profiles
/agents list

# Enable a profile
/agents enable blockchain
/agents enable cloud

# Disable a profile
/agents disable mobile
/agents disable specialized

# Reset to defaults (core + web + api)
/agents reset
```

### Auto-Activation (Built-in)

When you run `/hunt <target>`, the system auto-detects and enables needed profiles:

```bash
/hunt stake.com
# → Auto-enables "blockchain" profile (crypto detected)

/hunt app.example.com
# → Auto-enables "mobile" profile (mobile app detected)

/hunt *.s3.amazonaws.com
# → Auto-enables "cloud" profile (AWS detected)
```

**Detection Keywords**:
- Blockchain: `crypto`, `blockchain`, `stake`, `nft`, `defi`, `swap`
- Mobile: `app`, `mobile`, `ios`, `android`
- Cloud: `aws`, `s3`, `cloudfront`, `lambda`, `azure`, `gcp`
- IoT: `iot`, `device`, `firmware`

## Examples

### Example 1: Hunting a Web App

```bash
# Default profiles already active (core + web + api)
/hunt example.com

# Active: 43 agents
# Context: ~3-4k tokens
```

### Example 2: Hunting a Crypto Target

```bash
# Enable blockchain agents first
/agents enable blockchain

# Now hunt
/hunt stake.com

# Active: 45 agents (core + web + api + blockchain)
# Context: ~4.2k tokens

# After hunt, disable to save context
/agents disable blockchain
```

### Example 3: Cloud Pentest

```bash
# Enable cloud + infrastructure profiles
/agents enable cloud
/agents enable infrastructure

# Hunt
/hunt *.amazonaws.com

# Active: 58 agents
# Context: ~5.5k tokens
```

### Example 4: IoT Device Testing

```bash
# Enable specialized profile
/agents enable specialized

# Hunt
/hunt iot-device.local

# Active: 51 agents
# Context: ~4.8k tokens
```

## How It Works

Agents are stored as markdown files in `agents/` directory:

```
agents/
├── phased-hunter.md          # Active
├── jwt-analyzer.md           # Active
├── graphql-advanced-tester.md # Active
└── disabled/                  # Inactive agents
    ├── blockchain-security-scanner.md
    ├── mobile:android-reverser.md
    └── iot-security-tester.md
```

The `manage-agents.py` script moves agents between `agents/` and `agents/disabled/`:

- **Enable**: Move from `disabled/` to `agents/`
- **Disable**: Move from `agents/` to `disabled/`

Claude Code automatically discovers all `.md` files in `agents/` directory.

## Architecture

### Files

```
.claude-plugin/
├── agent-profiles.json    # Profile definitions
└── manage-agents.py       # Profile manager script

agents/
├── *.md                   # Active agents (loaded)
└── disabled/
    └── *.md               # Inactive agents (not loaded)

commands/
└── agents.md              # /agents command definition
```

### Profile Definition

`agent-profiles.json` defines 11 profiles with auto-activation rules:

```json
{
  "profiles": {
    "blockchain": {
      "description": "Blockchain/Web3 testing",
      "agents": [
        "blockchain-security-scanner",
        "blockchain:solidity-auditor"
      ]
    }
  },
  "default_enabled": ["core", "web", "api"],
  "auto_activate": {
    "rules": [
      {
        "condition": "target matches *.blockchain.*",
        "activate": ["blockchain"]
      }
    ]
  }
}
```

### Auto-Activation Logic

Built into `agents/phased-hunter.md` Phase 0.5:

1. Parse target domain
2. Check for keywords (crypto, mobile, aws, etc.)
3. Enable matching profiles
4. Verify agent count stays under 60 for optimal performance

## Performance Impact

| Configuration | Agents | Context Tokens | Performance |
|---------------|--------|----------------|-------------|
| All agents (old) | 155 | 16.4k | ⚠️ Slow |
| Default (new) | 43 | 3-4k | ✅ Fast |
| + Blockchain | 45 | 4.2k | ✅ Fast |
| + Cloud | 51 | 4.8k | ✅ Fast |
| + Specialized | 51 | 4.8k | ✅ Fast |
| Full stack | 60 | 5.8k | ✅ Fast |

**Rule of thumb**: Keep under 60 active agents for optimal performance.

## Best Practices

1. **Start with defaults** - Core + web + api covers 90% of targets
2. **Enable on-demand** - Only activate specialized profiles when needed
3. **Disable after use** - Free up context after finishing a hunt
4. **Use /agents status** - Check active agents before starting
5. **Let auto-activation work** - The system will detect most target types

## Troubleshooting

### Too many agents active

```bash
# Check status
/agents status

# Reset to defaults
/agents reset
```

### Missing needed agents

```bash
# Enable specific profile
/agents enable blockchain

# Or manually via Python
python3 .claude-plugin/manage-agents.py enable mobile
```

### Performance still slow

```bash
# Check total count
/agents status

# Should be under 60 agents
# If higher, disable unused profiles
/agents disable advanced
/agents disable recon
```

## Future Enhancements

- **Dynamic loading**: Load agents mid-hunt when new attack surface discovered
- **Usage tracking**: Auto-disable rarely-used agents
- **Custom profiles**: User-defined agent groups
- **Auto-cleanup**: Disable agents after hunt completion
- **Performance metrics**: Track context usage per profile

## Version History

- **v5.0.0** (2026-02-14): Initial agent profile system
  - 11 predefined profiles
  - Auto-activation for common targets
  - /agents command for manual management
  - Reduced default from 155 to 43 agents
  - Context usage: 16.4k → 3-4k tokens (~75% reduction)
