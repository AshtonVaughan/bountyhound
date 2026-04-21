# /agents - Manage Agent Profiles

**Quick agent profile management to optimize context usage.**

## Usage

```bash
/agents status              # Show current status
/agents list                # List all profiles
/agents reset               # Reset to defaults (core+web+api)
/agents enable <profile>    # Enable a profile
/agents disable <profile>   # Disable a profile
```

## How It Works

BountyHound has **155 specialized agents** organized into profiles:

- **core** (6 agents) - Always active
- **web** (28 agents) - Web app testing
- **api** (10 agents) - API testing
- **blockchain** (2 agents) - Web3/crypto
- **mobile** (3 agents) - iOS/Android
- **cloud** (9 agents) - AWS/GCP/Azure
- **infrastructure** (7 agents) - Network/DNS/CDN
- **advanced** (11 agents) - Research mode
- **recon** (6 agents) - Reconnaissance
- **specialized** (8 agents) - IoT/firmware/games
- **cicd** (2 agents) - CI/CD security

**Default enabled**: core + web + api (44 agents)

This reduces context usage from **16.4k tokens to ~3-4k tokens**.

## Auto-Activation

When you run `/hunt <target>`, the system auto-detects the target type and activates needed profiles:

- Crypto target → Enables `blockchain`
- Mobile app → Enables `mobile`
- AWS S3 found → Enables `cloud`
- IoT device → Enables `specialized`

## Implementation

```bash
# Call Python script
python3 "$CLAUDE_PLUGIN_ROOT/.claude-plugin/manage-agents.py" {{args}}
```

## Examples

```bash
# Before hunting a crypto target
/agents enable blockchain
/hunt stake.com

# After finishing, disable to save context
/agents disable blockchain

# Reset to clean state
/agents reset
```

## Status Display

Shows which profiles are active:

```
📊 Agent Status
   Active: 44 agents
   Disabled: 111 agents
   Total: 155 agents

🔍 Active Profiles:
   ✅ core: 6/6 agents
   ✅ web: 28/28 agents
   ✅ api: 10/10 agents
   ❌ blockchain: 0/2 agents
   ❌ mobile: 0/3 agents
```

## Profile Descriptions

- **core**: phased-hunter, discovery-engine, poc-validator, reporter-agent, auth-manager, scope-manager
- **web**: XSS, SQLi, CSRF, session attacks, JWT, OAuth, SSRF, XXE, template injection
- **api**: REST/GraphQL/gRPC testing, rate limits, versioning, authentication chains
- **blockchain**: Solidity auditing, smart contract analysis
- **mobile**: Android/iOS reverse engineering, mobile API testing
- **cloud**: AWS/GCP auditing, S3 enumeration, container security, serverless
- **infrastructure**: DNS, SSL/TLS, CDN, load balancers, reverse proxies
- **advanced**: Request smuggling, cache poisoning, WAF bypass, zero-day discovery
- **recon**: Subdomain enum, takeover detection, OSINT, tech fingerprinting
- **specialized**: IoT, firmware analysis, game hacking, kernel research
- **cicd**: Pipeline testing, supply chain analysis
