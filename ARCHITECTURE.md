# SecureCodeOps AI — System Architecture

## Architecture Overview

SecureCodeOps AI implements a **deterministic-first, supervisor-coordinated multi-agent architecture**:

```
                       ┌─────────────────────────┐
                       │   Developer / CI System │
                       └────────────┬────────────┘
                                    │ (ZIP Upload / Demo)
                                    ▼
                       ┌─────────────────────────┐
                       │  Safe Extraction Layer  │
                       │ (Zip Slip & Bomb Guard) │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │ Repository Analysis Agt │
                       │ (AST & Knowledge Graph) │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │    Supervisor Agent     │
                       └────────────┬────────────┘
        ┌──────────────┬────────────┼────────────┬──────────────┐
        ▼              ▼            ▼            ▼              ▼
┌──────────────┐┌──────────────┐┌──────────────┐┌──────────────┐┌──────────────┐
│ Vulnerability││ Dependency   ││ Threat Model ││ Code Review  ││ Compliance   │
│ Detection Agt││ Scanner Agt  ││ Agent(STRIDE)││ Agent (13 Dom││ Agent (OWASP │
│ (Semgrep/    ││ (Trivy/OSV   ││ (Impact x    ││ Auth/Crypto/ ││ GDPR/ISO/    │
│  Bandit/GitL)││  Exposure)   ││  Prob Risk)  ││  Logging)    ││ NIST/PCI)    │
└───────┬──────┘└──────────────┘└──────────────┘└──────────────┘└──────┬───────┘
        │                                                              │
        ▼                                                              │
┌──────────────┐                                                       │
│ AI Validation│                                                       │
│ Engine (LLM  │                                                       │
│  Exploit/FP) │                                                       │
└───────┬──────┘                                                       │
        │                                                              │
        ▼                                                              │
┌──────────────┐                                                       │
│ Patch Recom- │                                                       │
│ mendation Agt│                                                       │
│ (Sandbox Re- │                                                       │
│  scan Test)  │                                                       │
└───────┬──────┘                                                       │
        │                                                              │
        └───────────────────────┬──────────────────────────────────────┘
                                ▼
                       ┌─────────────────────────┐
                       │ Report Generation Agent │
                       │ (Score Formula, PDF/JSON│
                       └────────────┬────────────┘
                                    ▼
                       ┌─────────────────────────┐
                       │  SOC Dashboard & PDF    │
                       └─────────────────────────┘
```

## Core Principles

1. **Deterministic-First**: High-entropy regex, AST parsing, and security linters perform baseline detection. LLMs reason about exploitability and false positives without hallucinating CVEs.
2. **Context-Rich Knowledge Graph**: Nodes represent Files, Functions, Endpoints, DB sinks, Secrets, Dependencies, Threats, and Findings.
3. **Sandbox Patch Verification**: Patches are applied to isolated temporary sandboxes and re-scanned. Only patches with measured vulnerability reduction are marked verified.
4. **Transparent Scoring**: Security score mathematically accounts for Critical, High, Medium, Low vulnerabilities, Secret Exposure, Dependency Risk, and Compliance Gaps.
