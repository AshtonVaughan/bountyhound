# Claude Cowork — Complete Research Report

**Compiled:** 2026-03-09

---

## What Is Cowork?

Cowork is Anthropic's agentic desktop product that extends Claude Code's capabilities to non-developers. Instead of a chatbot that answers questions, Cowork is an agent that **does the work** — reading, creating, and editing files on your machine while coordinating multi-step tasks autonomously.

It lives as a separate tab inside the Claude Desktop app alongside Chat. When you switch to Cowork, Claude stops being conversational and starts being an executor.

**Core concept:** You describe the outcome you want, Cowork plans the approach, decomposes it into subtasks, executes them (including running code in a sandboxed VM), and delivers results directly to your filesystem.

---

## Timeline

| Date | Event |
|---|---|
| January 12, 2026 | Cowork announced as research preview for Max subscribers (macOS) |
| January 16, 2026 | Expanded to Pro subscribers |
| January 23, 2026 | Expanded to Team/Enterprise plans |
| January 30, 2026 | Enterprise features announced — software stocks dropped (ServiceNow, Salesforce, Snowflake, Intuit, Thomson Reuters) |
| February 10, 2026 | Windows support launched (full feature parity, x64 only) |
| February 24, 2026 | Major enterprise update: 13 plugins, 12 MCP connectors, private plugin marketplaces |

---

## How It Works Technically

### Architecture
- Built on the same foundations as Claude Code (Agent SDK)
- Runs code in an **isolated virtual machine** (Apple Virtualization Framework on macOS) — separate from your OS
- Files mount into sandboxed paths like `/sessions/[session-id]/mnt/`
- Downloads and boots custom Linux root filesystems for execution isolation
- Multi-step tasks run as coordinated parallel workstreams

### Execution Flow
1. Analyzes your request and creates an execution plan
2. Decomposes complex work into manageable subtasks
3. Executes operations within the isolated VM
4. Coordinates multiple workstreams simultaneously
5. Delivers results directly to your file system

### Key Difference from Claude Code
- **Interface-oriented, not capability-based** — Cowork wraps Claude Code functionality with simplified UX
- No terminal, no coding required — everything through natural language
- Pre-configured filesystem sandbox
- Designed for knowledge workers, not developers

---

## Features

### Core Capabilities
- **Local File Access** — read, write, create files without manual upload/download
- **Task Coordination** — breaks complex work into subtasks, manages parallel workstreams
- **Professional Outputs** — Excel with formulas/formatting, PowerPoint presentations, formatted documents
- **Extended Execution** — no conversation timeouts or context interruptions
- **Scheduled Tasks** — automate recurring work on custom schedules (`/schedule` command)
- **Web Search** — integrated search for research tasks
- **Browser Integration** — pairs with Claude in Chrome for browser-dependent tasks

### Skills System
Skills work inside Cowork — it proactively scans your task and pulls in relevant skills automatically. You can create custom skills to teach Claude your preferred workflows, formats, and approaches.

### Office Integration (Research Preview)
- Claude can open, edit, and pass context between Excel and PowerPoint add-ins
- Analyze data in Excel → move chart directly into a presentation
- Available on Mac with Max, Team, or Enterprise plans

### Scheduled Tasks
- Set recurring or on-demand tasks
- Tasks only run while computer is awake and Claude Desktop is open
- Use `/schedule` slash command or Scheduled sidebar section

---

## Enterprise Features (February 2026 Update)

### Plugins
Plugins customize how Claude works for specific roles, teams, and companies. Each bundles:
- **Skills** — domain-specific knowledge and workflows
- **Connectors** — MCP integrations with external tools
- **Slash commands** — quick actions with structured forms
- **Sub-agents** — specialized task handlers

### Available Plugin Templates

| Domain | Plugin |
|---|---|
| Finance | Financial Analysis, Investment Banking, Equity Research, Private Equity, Wealth Management |
| Business | HR, Design, Engineering, Operations |
| Partner | Brand Voice (Tribe AI), Slack (Salesforce), LSEG, S&P Global |

### MCP Connectors (12 new, Feb 2026)
Google Calendar, Google Drive, Gmail, DocuSign, Apollo, Clay, Outreach, Similarweb, MSCI, LegalZoom, FactSet, WordPress, Harvey

### Private Plugin Marketplace
Enterprise admins can:
- Build org-specific marketplaces
- Populate with Anthropic public plugins, partner plugins, or custom plugins
- Use private GitHub repos as plugin sources (beta)
- Per-user provisioning and auto-install
- Connector bundling control
- OpenTelemetry support for usage/cost tracking
- Company branding throughout

---

## Availability & Pricing

| Plan | Access | Price |
|---|---|---|
| Pro | Full Cowork access | $20/month |
| Max | Full Cowork + Office add-ins | $100-200/month |
| Team | Full Cowork + admin controls | Team pricing |
| Enterprise | Full + private marketplace + provisioning | Enterprise pricing |

**Platforms:** macOS, Windows (x64 only, no arm64)
**Status:** Research preview

---

## Permissions & Security

### Sandbox Isolation
- Code executes in isolated VM separate from host OS
- Controlled file and network access

### User Controls
- Choose which folders Claude can access
- Choose which MCP connectors to authorize
- Manage internet access permissions
- Explicit approval required before file deletion
- Approve significant actions before execution

### Safety Warnings
- Research preview with unique risks from agentic behavior + internet connectivity
- Prompt injection risk acknowledged — malicious content in files could alter Claude's plans
- Conversation history stored locally only
- Activity excluded from Audit Logs, Compliance APIs, Data Exports (not suitable for regulated workloads)
- Network egress permissions don't apply to web search

---

## Use Cases

### Document & File Management
- Organize hundreds of files into categorized folders
- Process receipts into formatted expense reports
- Batch rename files with consistent patterns (YYYY-MM-DD)
- Sort downloads folder by type and date

### Research & Analysis
- Synthesize web searches, articles, papers into coherent reports
- Extract themes and action items from meeting transcripts
- Analyze personal knowledge bases
- Competitive analysis across multiple sources

### Content Creation
- Generate Excel files with VLOOKUP, conditional formatting, multiple tabs
- Create PowerPoint presentations from notes
- Transform voice memos into polished documents
- Draft reports from scattered notes

### Data Work
- Statistical analysis and visualization
- Dataset cleaning and transformation
- Financial modeling
- Trend analysis

### Automation
- Daily news/work briefs
- Draft email replies
- Manage to-do lists via Notion
- Generate recurring reports
- Detect unused subscriptions

---

## Limitations

- No memory persistence between sessions
- Sessions cannot be shared with other users
- Desktop-only (no mobile, no web)
- No cross-device sync
- Desktop app must remain open during execution
- System sleep or app closure terminates sessions
- Higher resource consumption than standard chat
- arm64 Windows not supported

---

## Comparison: Cowork vs Claude Code vs Chat

| Capability | Chat | Cowork | Claude Code |
|---|---|---|---|
| Target user | Everyone | Knowledge workers | Developers |
| Interface | Web/Desktop chat | Desktop agent tab | Terminal CLI |
| File access | Upload/download | Direct filesystem | Direct filesystem |
| Code execution | No | Sandboxed VM | Local terminal |
| Multi-step tasks | Limited | Full orchestration | Full orchestration |
| Plugins/Skills | Skills only | Plugins + Skills + MCP | Skills + MCP |
| Scheduled tasks | No | Yes | No (use cron) |
| Office integration | No | Excel + PowerPoint | No |
| Requires coding | No | No | Yes |

---

## Market Impact

The January 30 enterprise announcement caused significant drops in enterprise SaaS stocks:
- ServiceNow, Salesforce, Snowflake, Intuit, Thomson Reuters all declined
- Media dubbed it the "SaaSpocalypse"
- Positioned as direct competition to enterprise workflow tools

---

## Key Takeaway for BountyHound

Cowork is essentially **Claude Code for non-technical work**, running in a sandboxed VM with the same agent architecture. For bug bounty purposes, Claude Code remains the right tool — Cowork's value is in document processing, data analysis, and enterprise workflow automation. However, Cowork's plugin/skill system and MCP connector architecture are the same ones used in Claude Code, so improvements to BountyHound skills work across both platforms.
