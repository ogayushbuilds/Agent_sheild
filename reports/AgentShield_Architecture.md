# AgentShield MVP Architecture

```mermaid
flowchart LR
    U[👤 User / Security Operator]
    A[🤖 Registered AI Agent]
    C[💬 Chat Transcript or Public Share Link]

    subgraph UI[🎨 React + TypeScript SOC Dashboard]
        O[Overview]
        AG[Agent Registry & Monitoring]
        MC[Monitor Chat]
        AQ[Approval Queue]
        AF[Audit Forensics]
        TR[Attack Trace Demo]
    end

    subgraph API[⚡ FastAPI Security Control Plane]
        V[① Validate Request\nPydantic + size limits]
        T[② Classify Trust\ntrusted / user / untrusted]
        PI[③ Prompt-Injection Detector\nDeterministic rules]
        SD[④ Sensitive-Data Detector\nSecrets / PII / medical data]
        PE[⑤ Policy Engine\nAllow / block / approval / redact]
        RS[⑥ Risk Scorer\nExplainable 0–100 score]
        D[⑦ Decision Gateway]
    end

    subgraph CONTROL[🛡️ Enforcement & Human Control]
        AL[✅ Allow]
        BL[⛔ Block]
        HR[🟠 Human Approval]
        RD[🔒 Redact]
        SIM[🧪 Safe Simulator\nNo real tools or uploads]
    end

    subgraph DATA[💾 SQLite Persistence]
        S[(Agent Sessions)]
        AR[(Action Requests)]
        SDT[(Security Decisions)]
        AP[(Approval Requests)]
        AU[(Append-only Audit Events)]
        AGT[(Agents)]
        CM[(Chat Monitor Sessions & Events)]
        DT[(Demo Traces)]
    end

    U --> UI
    A -->|Every proposed action| V
    C -->|Pasted text or approved public-share import| V
    UI --> API

    V --> T --> PI --> SD --> PE --> RS --> D
    D --> AL --> SIM
    D --> BL
    D --> HR
    D --> RD

    V -. session .-> S
    V -. action .-> AR
    D -. decision .-> SDT
    HR -. queue .-> AP
    D -. evidence .-> AU
    AG -. configuration .-> AGT
    C -. transcript events .-> CM
    TR -. deterministic fixture .-> DT

    AU --> AF
    AP --> AQ
    AR --> AG
    CM --> MC
    DT --> TR

    classDef user fill:#19324a,stroke:#58d8b5,color:#ffffff,stroke-width:2px;
    classDef ui fill:#153b58,stroke:#26c6da,color:#ffffff,stroke-width:2px;
    classDef api fill:#173b35,stroke:#55d7b4,color:#ffffff,stroke-width:2px;
    classDef control fill:#382b1e,stroke:#e7b45e,color:#ffffff,stroke-width:2px;
    classDef data fill:#241d36,stroke:#a88de4,color:#ffffff,stroke-width:2px;

    class U,A,C user;
    class O,AG,MC,AQ,AF,TR ui;
    class V,T,PI,SD,PE,RS,D api;
    class AL,BL,HR,RD,SIM control;
    class S,AR,SDT,AP,AU,AGT,CM,DT data;
```

## Request path

1. An agent proposes an action or a user submits chat/transcript content.
2. FastAPI validates the request and applies payload limits.
3. AgentShield classifies the source as trusted, user, untrusted, or unknown.
4. Deterministic detectors inspect prompt-injection patterns and sensitive data.
5. The policy engine evaluates tools, destinations, data classification, and agent configuration.
6. The risk scorer produces a clamped, explainable score from 0 to 100.
7. The gateway returns one decision: allow, block, approval required, or redact.
8. Only allowed actions can reach the safe simulator in the MVP.
9. Decisions, approvals, detector evidence, and audit events are persisted with redaction.

## Security boundaries

- **Untrusted content boundary:** webpage and imported chat content are data, never instructions.
- **Tool boundary:** simulator tools never execute real shell commands, uploads, HTTP requests, or emails.
- **Destination boundary:** malformed, private, local, or unapproved destinations fail closed.
- **Approval boundary:** approvals are hash-bound, expiring, single-use, and audited.
- **Data boundary:** secrets and sensitive values are redacted before persistence and display.
- **Provider boundary:** the deterministic simulator works without an LLM provider.

## Technology map

| Layer | Technology | Responsibility |
|---|---|---|
| Dashboard | React, TypeScript, Vite, Tailwind CSS | SOC screens, agents, chat monitoring, approvals, demos |
| API | Python, FastAPI, Pydantic | Typed endpoints, validation, gateway orchestration |
| Detection | Deterministic Python rules | Prompt injection and sensitive-data findings |
| Decisioning | Policy engine and risk scorer | Explainable policy and risk decisions |
| Persistence | SQLAlchemy, SQLite | Sessions, actions, agents, approvals, traces, audits |
| Quality | Pytest, Vitest, React Testing Library | Unit, integration, and UI regression tests |

> AgentShield uses defense in depth. The risk score and detector results are decision aids, not proof of safety or a guarantee of perfect security.
