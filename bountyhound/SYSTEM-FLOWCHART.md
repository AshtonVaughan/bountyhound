# BountyHound System Flowchart

## Master System Architecture

```mermaid
graph TB
    Start([User Input]) --> CMD{Command Type?}

    CMD -->|/hunt target| Hunt[Phased Hunter Agent]
    CMD -->|/phunt target| Hunt
    CMD -->|/recon domain| Recon[Discovery Engine - Recon Only]
    CMD -->|/creds action| Creds[Auth Manager]

    Hunt --> P1[PHASE 1: RECON]
    Hunt --> P2[PHASE 2: DISCOVERY]
    Hunt --> P3[PHASE 3: PARALLEL TESTING]
    Hunt --> P4[PHASE 4: SYNC & EXPLOIT]
    Hunt --> P5[PHASE 5: REPORTING]

    P1 --> P2
    P2 --> P3
    P3 --> P4
    P4 --> P5
    P5 --> Output([Reports & Evidence])

    Recon --> DB[(SQLite DB)]
    DB --> Output

    Creds --> CredStore[.env Files]
    CredStore --> P3

    style Hunt fill:#f96,stroke:#333,stroke-width:4px
    style Output fill:#9f6,stroke:#333,stroke-width:4px
    style DB fill:#69f,stroke:#333,stroke-width:2px
```

---

## Detailed Phased Hunt Flow

```mermaid
graph TB
    Start([/hunt example.com]) --> Check{Target in Scope?}

    Check -->|No| Abort([Error: Out of Scope])
    Check -->|Yes| Phase1[PHASE 1: RECON]

    subgraph PHASE1[" PHASE 1: RECON (~5 min) "]
        R1[Run: bountyhound recon example.com]
        R2[Subfinder: Find subdomains]
        R3[httpx: Probe live hosts]
        R4[nmap: Port scanning]
        R5[Save to ~/.bountyhound/bountyhound.db]

        R1 --> R2 --> R3 --> R4 --> R5
    end

    Phase1 --> Phase2[PHASE 1.5: DISCOVERY ENGINE]

    subgraph PHASE2[" PHASE 1.5: DISCOVERY (~2 min) "]
        D1[Load recon data from DB]
        D2[LLM: Pattern synthesis]
        D3[LLM: Anomaly detection]
        D4[LLM: Technology fingerprinting]
        D5[Generate 5-15 hypothesis cards]
        D6{Novel vectors found?}

        D1 --> D2 --> D3 --> D4 --> D5 --> D6
    end

    Phase2 --> Phase3[PHASE 2: PARALLEL TESTING]

    subgraph PHASE3[" PHASE 2: PARALLEL TESTING (~15 min) "]
        direction LR

        T1A[Track A: bountyhound scan]
        T1B[Nuclei templates]
        T1C[Background process]

        T2A[Track B: Browser Testing]
        T2B[Test hypothesis cards]
        T2C[Manual attack chains]
        T2D[Injection attacks]
        T2E[Auth bypass]
        T2F[IDOR testing]

        T1A --> T1B --> T1C
        T2A --> T2B --> T2C
        T2C --> T2D
        T2C --> T2E
        T2C --> T2F
    end

    Phase3 --> Phase4[PHASE 3: SYNC]

    subgraph PHASE4[" PHASE 3: SYNC (~2 min) "]
        S1[Merge CLI findings]
        S2[Merge browser findings]
        S3{Findings > 0?}
        S4[Gap analysis]
        S5[Trigger discovery engine again]

        S1 --> S2 --> S3
        S3 -->|No| S4 --> S5 --> S2
        S3 -->|Yes| S6[Proceed to exploitation]
    end

    Phase4 --> Phase5[PHASE 4: EXPLOIT]

    subgraph PHASE5[" PHASE 4: EXPLOIT (~5 min) "]
        E1[Select high-value findings]
        E2[POC Validator: curl validation]
        E3{Verified?}
        E4[Capture evidence]
        E5[Screenshots]
        E6[Request/Response logs]
        E7[Discard false positive]

        E1 --> E2 --> E3
        E3 -->|Yes| E4 --> E5 --> E6
        E3 -->|No| E7
    end

    Phase5 --> Phase6[PHASE 5: REPORTING]

    subgraph PHASE6[" PHASE 5: REPORTING (~3 min) "]
        RP1[Reporter Agent: Generate REPORT.md]
        RP2[Create individual VERIFIED-*.md files]
        RP3[Organize screenshots]
        RP4[Calculate severity/bounty estimates]
        RP5[Save to ~/bounty-findings/target/]

        RP1 --> RP2 --> RP3 --> RP4 --> RP5
    end

    Phase6 --> End([Hunt Complete])

    style Start fill:#9f6,stroke:#333,stroke-width:4px
    style End fill:#f96,stroke:#333,stroke-width:4px
    style PHASE1 fill:#e1f5ff,stroke:#333,stroke-width:2px
    style PHASE2 fill:#fff4e1,stroke:#333,stroke-width:2px
    style PHASE3 fill:#ffe1f5,stroke:#333,stroke-width:2px
    style PHASE4 fill:#e1ffe1,stroke:#333,stroke-width:2px
    style PHASE5 fill:#f5e1ff,stroke:#333,stroke-width:2px
    style PHASE6 fill:#ffe1e1,stroke:#333,stroke-width:2px
```

---

## Agent Interaction Flow

```mermaid
graph LR
    User([User]) --> Orchestrator[Hunt Orchestrator]

    Orchestrator --> Discovery[Discovery Engine]
    Orchestrator --> Auth[Auth Manager]
    Orchestrator --> API[API Tester]
    Orchestrator --> Injection[Injection Tester]
    Orchestrator --> AuthBoundary[Authorization Boundary Tester]
    Orchestrator --> Innovation[Innovation Agent]

    Discovery --> Hypotheses[(Hypothesis Cards)]

    API --> Evidence[Evidence Collector]
    Injection --> Evidence
    AuthBoundary --> Evidence
    Innovation --> Evidence

    Evidence --> Validator[POC Validator]

    Validator -->|Verified| Reporter[Reporter Agent]
    Validator -->|Failed| Discard[/Discard/]

    Reporter --> Output[(Reports & Evidence)]

    Auth --> Creds[(.env Files)]
    Creds --> API
    Creds --> AuthBoundary

    Skills[Skills Library] -.-> API
    Skills -.-> Injection
    Skills -.-> AuthBoundary
    Skills -.-> Innovation

    style Orchestrator fill:#f96,stroke:#333,stroke-width:4px
    style Reporter fill:#9f6,stroke:#333,stroke-width:4px
    style Discovery fill:#ff9,stroke:#333,stroke-width:2px
    style Innovation fill:#f9f,stroke:#333,stroke-width:2px
```

---

## Discovery Engine Deep Dive

```mermaid
graph TB
    Input[(Recon Data)] --> Load[Load from SQLite]

    Load --> Analysis{Analysis Type}

    Analysis -->|Pattern| P1[Identify patterns]
    Analysis -->|Anomaly| A1[Detect anomalies]
    Analysis -->|Tech| T1[Fingerprint stack]

    P1 --> P2[Common endpoints]
    P1 --> P3[URL structures]
    P1 --> P4[Parameter naming]

    A1 --> A2[Unusual headers]
    A1 --> A3[Error messages]
    A1 --> A4[Timing differences]

    T1 --> T2[Framework detection]
    T1 --> T3[Library versions]
    T1 --> T4[API patterns]

    P2 --> Synthesize[LLM Synthesis]
    P3 --> Synthesize
    P4 --> Synthesize
    A2 --> Synthesize
    A3 --> Synthesize
    A4 --> Synthesize
    T2 --> Synthesize
    T3 --> Synthesize
    T4 --> Synthesize

    Synthesize --> Generate[Generate Hypothesis Cards]

    Generate --> H1[Card 1: GraphQL introspection]
    Generate --> H2[Card 2: IDOR on /api/users/]
    Generate --> H3[Card 3: XXE in XML endpoint]
    Generate --> H4[Card 4: JWT secret brute force]
    Generate --> H5[Card 5-15: Additional vectors]

    H1 --> Test[Browser Testing Phase]
    H2 --> Test
    H3 --> Test
    H4 --> Test
    H5 --> Test

    Test --> Results{Results?}
    Results -->|Found| Evidence[(Evidence)]
    Results -->|None| Gap[Gap Analysis]

    Gap --> Refine[Refine Hypotheses]
    Refine --> Generate

    style Input fill:#69f,stroke:#333,stroke-width:2px
    style Generate fill:#f96,stroke:#333,stroke-width:2px
    style Evidence fill:#9f6,stroke:#333,stroke-width:2px
```

---

## Credential Management Flow

```mermaid
graph TB
    Start([/creds command]) --> Action{Action Type?}

    Action -->|list| List[Show all targets with creds]
    Action -->|show target| Show[Display credentials for target]
    Action -->|add target| Add[Interactive credential setup]
    Action -->|refresh target| Refresh[Refresh expired tokens]

    List --> Display1[(List all .env files)]
    Show --> Display2[(Load and show .env)]

    Add --> A1{Auth Type?}
    A1 -->|OAuth| OAuth[Browser OAuth flow]
    A1 -->|Email/Pass| Login[Browser login form]
    A1 -->|API Key| Manual[Manual input]

    OAuth --> Capture[Intercept tokens from network]
    Login --> Capture
    Manual --> Store

    Capture --> Extract[Extract tokens/cookies]
    Extract --> Store[Save to .env file]

    Store --> Path[~/bounty-findings/target/credentials/target-creds.env]

    Refresh --> R1[Load existing .env]
    R1 --> R2{Token type?}
    R2 -->|OAuth| R3[Use refresh_token]
    R2 -->|Session| R4[Re-authenticate]
    R3 --> R5[Request new access_token]
    R4 --> R5
    R5 --> Update[Update .env file]

    Path --> End([Credentials Ready])
    Update --> End
    Display1 --> End
    Display2 --> End

    style Start fill:#9f6,stroke:#333,stroke-width:4px
    style End fill:#f96,stroke:#333,stroke-width:4px
    style Path fill:#69f,stroke:#333,stroke-width:2px
```

---

## Browser Testing Workflow

```mermaid
graph TB
    Start([Hypothesis Card]) --> Nav[Navigate to target URL]

    Nav --> Snap[Take snapshot]
    Snap --> Analyze[Analyze page structure]

    Analyze --> Type{Attack Type?}

    Type -->|XSS| XSS1[Inject payloads]
    Type -->|SQLi| SQL1[Inject SQL]
    Type -->|IDOR| IDOR1[Modify IDs]
    Type -->|Auth| Auth1[Test bypass]

    XSS1 --> XSS2[Monitor console]
    XSS2 --> XSS3{XSS fired?}
    XSS3 -->|Yes| Evidence

    SQL1 --> SQL2[Check errors]
    SQL2 --> SQL3{SQL error?}
    SQL3 -->|Yes| Evidence

    IDOR1 --> IDOR2[Compare responses]
    IDOR2 --> IDOR3{Access granted?}
    IDOR3 -->|Yes| Evidence

    Auth1 --> Auth2[Bypass attempts]
    Auth2 --> Auth3{Bypassed?}
    Auth3 -->|Yes| Evidence

    Evidence[Capture Evidence] --> SS[Screenshot]
    SS --> Net[Network logs]
    Net --> Validate[POC Validator: curl test]

    Validate --> V{Verified?}
    V -->|Yes| Save[Save VERIFIED-*.md]
    V -->|No| Discard[/Discard/]

    XSS3 -->|No| Next
    SQL3 -->|No| Next
    IDOR3 -->|No| Next
    Auth3 -->|No| Next

    Next[Next hypothesis] --> Type

    Save --> End([Finding Recorded])

    style Start fill:#9f6,stroke:#333,stroke-width:4px
    style Evidence fill:#ff9,stroke:#333,stroke-width:2px
    style Save fill:#f96,stroke:#333,stroke-width:2px
```

---

## Skills Library Structure

```mermaid
graph TB
    Skills[Skills Library] --> Injection[injection-attacks/]
    Skills --> Auth[auth-attacks/]
    Skills --> WAF[waf-bypass/]
    Skills --> Scope[scope-parser/]
    Skills --> Report[report-psychology/]
    Skills --> Cred[credential-manager/]

    Injection --> XSS[XSS payloads]
    Injection --> SQLi[SQL injection]
    Injection --> SSTI[Template injection]
    Injection --> XXE[XXE payloads]
    Injection --> CMD[Command injection]

    Auth --> JWT[JWT attacks]
    Auth --> OAuth[OAuth bypass]
    Auth --> Session[Session attacks]
    Auth --> 2FA[2FA bypass]

    WAF --> Encoding[Encoding techniques]
    WAF --> Obfuscation[Payload obfuscation]
    WAF --> Fragmentation[Request fragmentation]

    Scope --> Parse[Parse bounty program rules]
    Scope --> Validate[Validate targets]
    Scope --> Exclude[Check exclusions]

    Report --> Psychology[Writing techniques]
    Report --> Templates[Report templates]
    Report --> Severity[Severity scoring]

    Cred --> Storage[.env management]
    Cred --> Refresh[Token refresh]
    Cred --> MultiUser[Multi-user support]

    style Skills fill:#f96,stroke:#333,stroke-width:4px
    style Injection fill:#ff9,stroke:#333,stroke-width:2px
    style Auth fill:#9f9,stroke:#333,stroke-width:2px
    style WAF fill:#f9f,stroke:#333,stroke-width:2px
```

---

## Output Generation Flow

```mermaid
graph TB
    Start[(Verified Findings)] --> Reporter[Reporter Agent]

    Reporter --> R1[Load all findings]
    R1 --> R2[Calculate severity]
    R2 --> R3[Estimate bounty]
    R3 --> R4[Generate summary]

    R4 --> Files{Output Files}

    Files --> F1[REPORT.md]
    Files --> F2[VERIFIED-F1.md]
    Files --> F3[VERIFIED-F2.md]
    Files --> F4[VERIFIED-F3.md]
    Files --> F5[browser-findings.md]

    F1 --> Summary[Executive Summary]
    F1 --> Stats[Statistics]
    F1 --> Timeline[Timeline]
    F1 --> Breakdown[Severity Breakdown]

    F2 --> Detail[Detailed Finding]
    F2 --> POC[Proof of Concept]
    F2 --> Impact[Impact Analysis]
    F2 --> Remediation[Remediation Steps]

    F3 --> Detail
    F4 --> Detail

    Screenshots[(screenshots/)] --> F2
    Screenshots --> F3
    Screenshots --> F4

    Summary --> Path[~/bounty-findings/target/]
    Detail --> Path
    Screenshots --> Path

    Path --> Platform{Platform?}
    Platform -->|HackerOne| H1[Format for HackerOne]
    Platform -->|Bugcrowd| BC[Format for Bugcrowd]
    Platform -->|Private| Custom[Custom format]

    H1 --> Submit([Ready to Submit])
    BC --> Submit
    Custom --> Submit

    style Start fill:#9f6,stroke:#333,stroke-width:4px
    style Reporter fill:#f96,stroke:#333,stroke-width:4px
    style Submit fill:#69f,stroke:#333,stroke-width:4px
```

---

## Timeline: Full Hunt Execution

```mermaid
gantt
    title BountyHound Hunt Timeline (Total: ~29 minutes)
    dateFormat mm:ss
    axisFormat %M:%S

    section Phase 1: Recon
    bountyhound recon           :00:00, 5m
    subfinder                   :00:00, 2m
    httpx                       :02:00, 2m
    nmap                        :04:00, 1m

    section Phase 1.5: Discovery
    Load recon data             :05:00, 30s
    LLM analysis                :05:30, 1m
    Generate hypotheses         :06:30, 30s

    section Phase 2: Parallel Testing
    Track A: nuclei scan        :07:00, 15m
    Track B: browser test 1     :07:00, 2m
    Track B: browser test 2     :09:00, 2m
    Track B: browser test 3     :11:00, 2m
    Track B: browser test 4     :13:00, 2m
    Track B: browser test 5     :15:00, 2m

    section Phase 3: Sync
    Merge findings              :22:00, 1m
    Gap analysis                :23:00, 1m

    section Phase 4: Exploit
    POC validation              :24:00, 3m
    Capture evidence            :27:00, 2m

    section Phase 5: Report
    Generate reports            :29:00, 3m
```

---

## Data Flow Diagram

```mermaid
graph LR
    subgraph Input
        User([User Command])
        Target[Target Domain]
    end

    subgraph Processing
        CLI[bountyhound CLI]
        Browser[Playwright Browser]
        LLM[Discovery Engine]
    end

    subgraph Storage
        DB[(SQLite DB)]
        ENV[(.env Files)]
        Files[(Finding Files)]
    end

    subgraph Output
        Reports[REPORT.md]
        Verified[VERIFIED-*.md]
        Screenshots[screenshots/]
    end

    User --> CLI
    User --> Browser
    Target --> CLI

    CLI --> DB
    DB --> LLM
    LLM --> Browser

    Browser --> Files
    ENV --> Browser

    Files --> Reports
    Files --> Verified
    Browser --> Screenshots

    style User fill:#9f6,stroke:#333,stroke-width:4px
    style Reports fill:#f96,stroke:#333,stroke-width:4px
    style DB fill:#69f,stroke:#333,stroke-width:2px
```

---

## Component Count Breakdown

```mermaid
pie title BountyHound Components (155 total)
    "Core Agents (16)" : 16
    "API Testing (25)" : 25
    "Injection Testing (20)" : 20
    "Authorization (15)" : 15
    "Cloud/Infrastructure (18)" : 18
    "Mobile Security (12)" : 12
    "Advanced Analysis (20)" : 20
    "Automation & Reporting (15)" : 15
    "Protocol Testing (14)" : 14
```

