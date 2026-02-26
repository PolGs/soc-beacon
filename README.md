# SOC Beacon — Open Source AI Security Platform

**The open source security operations center (SOC) platform that uses artificial intelligence to analyze, classify, and correlate your logs — so your team catches threats that manual analysis misses.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-16-black)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue)](https://www.typescriptlang.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

> **Ship an AI-powered SOC in minutes, not months.** SOC Beacon replaces the complexity of enterprise SIEM deployments with a single platform that ingests logs, generates alerts, enriches incidents with AI and threat intelligence, and gives analysts a fast triage workflow — all from one dashboard.

---

<img width="1200" height="1257" alt="image" src="https://github.com/user-attachments/assets/8bae7fcb-170f-4b69-acce-0803fd94e4e2" />



## The Problem

Security teams drown in logs. Traditional SIEMs cost six figures, take months to deploy, and still require analysts to manually triage thousands of alerts. Small and mid-size teams are left choosing between "too expensive" and "too manual."

**The result:** threats slip through, analysts burn out, and critical incidents get buried in noise.

## The Solution

SOC Beacon is an **open source AI security platform** that gives every team enterprise-grade detection and response:

- **AI log analysis and classification** — LLM-powered agents analyze every alert with multiple perspectives, assign verdicts, and surface what matters
- **Automatic threat intelligence correlation** — 8 integrated threat feeds enrich alerts with IOC context before an analyst ever sees them
- **Detection engine support** — YARA and Sigma rules catch known patterns while AI catches what rules miss
- **Zero-infrastructure deployment** — runs as a single Next.js application with an embedded database, no Elasticsearch/Splunk stack required

---

## Key Features

### AI-Powered Log Analysis and Threat Classification

SOC Beacon uses artificial intelligence to go beyond pattern matching. Configure 1–4 AI analyst agents per alert, each examining the event from a different security perspective. The platform supports **OpenAI** (GPT-4, GPT-4 mini), **Anthropic Claude**, and **local models via Ollama** — giving you full control over cost and data privacy.

Each alert receives:
- An **AI confidence score** (0–100) with visual risk indicators
- A **heuristics score** from rule-based detection engines
- An **automated verdict**: `malicious`, `suspicious`, or `false_positive`
- **Actionable recommendations** for analyst follow-up
- **MITRE ATT&CK mapping** for standardized threat classification

### Integrated Threat Intelligence Enrichment

Every alert is automatically enriched with context from **8 threat intelligence sources** — no manual lookups required:

| Feed | Type | API Key Required |
|------|------|:---:|
| AbuseIPDB | IP reputation scoring | Optional |
| AlienVault OTX | Indicators of compromise | Optional |
| GeoIP | IP geolocation | No |
| Google Safe Browsing | Malicious URL detection | Optional |
| Spamhaus DROP/EDROP | Spam and botnet blocklists | No |
| ThreatFox | Malware IOC database | No |
| URLhaus | Malicious URL tracking | No |
| VirusTotal | File and URL analysis | Optional |

### Detection Engines — YARA and Sigma Rules

Run **YARA rules** for pattern-based scanning (string, hex, and regex matching) alongside **Sigma rules** for structured log detection. Both engines are configurable from the dashboard settings — enable, disable, and manage rules without touching config files.

### Multi-Source Log Ingestion

Accept logs from any source through multiple ingestion methods:

- **REST API** (`POST /api/v1/logs`) — send structured JSON with API key authentication
- **Syslog listener** — receive logs over UDP, TCP, or TLS on configurable ports
- **CSV file upload** — bulk import historical logs through the dashboard
- **Batch ingestion** — send multiple log entries in a single API call

### Analyst Triage Workflow

A purpose-built dashboard for security operations:

- **Sortable, filterable alert tables** with toggleable columns for high-volume scanning
- **Alert detail views** with tabbed investigation context: AI Analysis, MITRE ATT&CK, Threat Intel, Raw Log
- **Verdict management**: mark alerts as `malicious`, `suspicious`, or `false_positive`
- **Incident status tracking**: `unassigned` → `in_progress` → `resolved`
- **Dual scoring rings** — AI Score and Heuristics Score displayed as circular visual indicators
- **Alert timeline** and **MITRE ATT&CK heatmap** visualizations

### Cost-Aware AI Integration

Unlike platforms that burn through API budgets, SOC Beacon provides granular cost controls:

- Choose your LLM provider and model (including free local models via Ollama)
- Configure agent count per alert (1–4 analysts)
- Set max token limits and temperature
- Toggle auto-enrichment on or off
- Set confidence thresholds for automatic incident escalation

---

## Quick Start

### Prerequisites

- Node.js 18+ and pnpm (or npm/yarn)

### Install and Run

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/soc-beacon.git
cd soc-beacon

# Install dependencies
pnpm install

# Start the platform
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000) — the database initializes automatically on first run.

### Reset Admin Password (Without Login)

If you cannot log in as `admin`, you can reset the password directly in the local DB.

1. Stop the app.
2. Run this in project root (PowerShell):

NewStrongPass123!

```powershell
@'
const fs = require("fs")
const path = require("path")
const initSqlJs = require("sql.js")
const bcrypt = require("bcryptjs")

async function main() {
  const SQL = await initSqlJs()
  const dbPath = process.env.SOC_BEACON_DB_PATH || path.join(process.cwd(), "data", "soc-beacon.db")
  const db = new SQL.Database(fs.readFileSync(dbPath))

  const newPassword = process.env.NEW_ADMIN_PASSWORD || "NewStrongPass123!"
  const hash = bcrypt.hashSync(newPassword, 10)

  db.run(
    "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE username = ?",
    [hash, "admin"]
  )

  fs.writeFileSync(dbPath, Buffer.from(db.export()))
  console.log("Admin password reset.")
  console.log("Username: admin")
  console.log(`Password: ${newPassword}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
'@ | node
```

Optional: set a custom password before running:

```powershell
$env:NEW_ADMIN_PASSWORD = "YourStrongPasswordHere"
```

Then start again:

```bash
npm run dev
```

### Send Your First Log

```bash
curl -X POST http://localhost:3000/api/v1/logs \
  -H "Content-Type: application/json" \
  -H "Auhtorization: Bearer YOUR_API_KEY" \
  -d '{
    "message": "Failed SSH login from 203.0.113.50 to root@prod-server-01",
    "source": "auth-server",
    "severity": "high"
  }'

curl -X POST http://localhost:3000/api/v1/logs -H "Content-Type: application/json" -H "Authorization: Bearer YOUR_API_KEY" -d "{\"message\":\"Failed SSH login from 203.0.113.50 to root@prod-server-01\",\"source\":\"auth-server\",\"severity\":\"high\"}"
```

The log is parsed, classified, enriched with threat intelligence, analyzed by AI (if configured), and surfaced as an actionable alert in the dashboard.

### Configure AI Enrichment

Navigate to **Settings → AI/LLM** in the dashboard to connect your preferred provider:

| Provider | Setup |
|----------|-------|
| **OpenAI** | Add your API key, select model (GPT-4, GPT-4 mini) |
| **Anthropic** | Add your API key, select Claude model |
| **Ollama (Local)** | Point to your local Ollama endpoint — zero cost, full privacy |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SOC Beacon                               │
│                                                                 │
│  ┌──────────┐   ┌──────────────┐   ┌────────────────────────┐  │
│  │ REST API │──▶│  Ingestion   │──▶│  Detection Engines      │  │
│  │ Syslog   │   │  Pipeline    │   │  (YARA + Sigma Rules)   │  │
│  │ CSV      │   │  (Parse +    │   └────────────┬───────────┘  │
│  └──────────┘   │   Classify)  │                │              │
│                 └──────────────┘                ▼              │
│                                    ┌────────────────────────┐  │
│                                    │   Alert Generation     │  │
│                                    └────────────┬───────────┘  │
│                                                 │              │
│                      ┌──────────────────────────┼──────┐       │
│                      ▼                          ▼      │       │
│          ┌──────────────────┐     ┌─────────────────┐  │       │
│          │  AI Enrichment   │     │  Threat Intel    │  │       │
│          │  (OpenAI/Claude/ │     │  (8 Feeds)       │  │       │
│          │   Ollama)        │     └─────────────────┘  │       │
│          └──────────────────┘                          │       │
│                      │              ┌──────────────────┘       │
│                      ▼              ▼                          │
│          ┌───────────────────────────────────────────────┐     │
│          │          Analyst Dashboard                     │     │
│          │  (Alerts · Logs · MITRE · Settings · Triage)  │     │
│          └───────────────────────────────────────────────┘     │
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐    │
│  │  Embedded SQLite Database (SQL.js) — Zero Config       │    │
│  └────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | Next.js 16, React 19, TypeScript, Tailwind CSS, shadcn/ui, Recharts |
| **Backend** | Next.js API Routes, Node.js |
| **Database** | SQL.js (embedded SQLite, file-persisted) |
| **AI/LLM** | OpenAI SDK, Anthropic SDK, Ollama |
| **Detection** | YARA rule engine, Sigma rule engine |

---

## API Reference

### Log Ingestion

```
POST /api/v1/logs          — Ingest single or batch logs
GET  /api/v1/logs          — Query logs with filters
```

### Alert Management

```
GET    /api/v1/alerts      — List alerts (filterable, paginated)
GET    /api/v1/alerts/:id  — Get alert with full enrichment
PUT    /api/v1/alerts/:id  — Update verdict or incident status
DELETE /api/v1/alerts/:id  — Remove alert
POST   /api/v1/alerts/:id/enrich — Trigger manual AI enrichment
```

### Utilities

```
POST /api/v1/upload        — Upload CSV/log files
GET  /api/v1/health        — System health check
```

All endpoints support API key authentication via `Authorization: Bearer <key>` or `X-API-Key: <key>` headers.

---

## Who Is SOC Beacon For?

| Role | Use Case |
|------|----------|
| **SOC Analysts** | Fast daily triage with AI-assisted investigation and verdict workflows |
| **Security Engineers** | Build and test detection pipelines with YARA/Sigma rules and AI enrichment |
| **Blue Teams (SMB)** | Deploy practical SOC capabilities without enterprise SIEM overhead |
| **Security Consultants** | Run incident monitoring for multiple clients from a single platform |
| **Students & Researchers** | Learn security operations with a real, functional SOC environment |
| **Homelab Operators** | Monitor home network security with AI-powered log analysis |

---

## SOC Beacon vs. Traditional SIEM

| Capability | SOC Beacon | Enterprise SIEM | ELK Stack |
|------------|:----------:|:----------------:|:---------:|
| AI-powered log analysis | Yes | Partial | No |
| Built-in threat intel (8 feeds) | Yes | Varies | No |
| YARA + Sigma detection | Yes | Varies | No |
| Deployment time | Minutes | Weeks–Months | Days |
| Infrastructure required | None (embedded DB) | Significant | Moderate |
| Cost | Free & open source | $50K–$500K+/yr | Free (infra cost) |
| AI provider flexibility | 3 providers + local | Vendor-locked | N/A |
| Analyst triage workflow | Built-in | Built-in | Manual setup |

---

## Configuration

SOC Beacon is fully configurable from the dashboard UI:

- **General** — Instance name, log retention period
- **Ingestion** — API key management, syslog listener (UDP/TCP/TLS)
- **AI/LLM** — Provider, model, tokens, temperature, agent count, auto-enrich
- **YARA** — Enable/disable rules, auto-update toggle
- **Sigma** — Enable/disable, rules path, max rules limit
- **Threat Intel** — API key management for premium feeds
- **Output** — Syslog forwarding in CEF, LEEF, or JSON format
- **Authentication** — User management and access control

---

## Project Structure

```
soc-beacon/
├── app/                    # Next.js App Router
│   ├── api/v1/            # REST API endpoints
│   ├── dashboard/         # SOC analyst dashboard
│   └── login/             # Authentication
├── components/            # React UI components
├── lib/
│   ├── db/               # Database operations (SQLite)
│   ├── ingestion/        # Log parsing and syslog listener
│   ├── llm/              # AI provider integrations
│   ├── pipeline/         # Ingestion and classification pipeline
│   ├── sigma/            # Sigma rule engine
│   ├── threat-intel/     # 8 threat intelligence feed integrations
│   └── yara/             # YARA rule engine
└── hooks/                # Custom React hooks
```

---

## Roadmap

- [ ] Real-time alert streaming via WebSocket
- [ ] Full Sigma semantic evaluation (beyond keyword matching)
- [ ] Multi-tenant support for managed security providers
- [ ] Automated playbook execution (SOAR capabilities)
- [ ] Expanded threat feed integrations
- [ ] Docker and Kubernetes deployment manifests
- [ ] Role-based access control (RBAC)
- [ ] Alert correlation engine for incident grouping

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/soc-beacon.git

# Create a feature branch
git checkout -b feature/your-feature

# Make changes and submit a PR
```

---

## Community

- [GitHub Issues](https://github.com/YOUR_USERNAME/soc-beacon/issues) — Bug reports and feature requests
- [GitHub Discussions](https://github.com/YOUR_USERNAME/soc-beacon/discussions) — Questions and community chat

---

## License

SOC Beacon is open source software licensed under the [MIT License](LICENSE).

---

## Acknowledgments

Built with [Next.js](https://nextjs.org/), [shadcn/ui](https://ui.shadcn.com/), [SQL.js](https://sql.js.org/), and the security community's collective knowledge.

---

<sub>**Keywords:** open source security platform, AI security platform, artificial intelligence security platform, AI log analysis, AI log analyst, AI log classification and correlation, open source SIEM alternative, security operations center, SOC platform, threat intelligence platform, log analysis tool, incident response platform, YARA rules, Sigma rules, MITRE ATT&CK, threat detection, security automation, AI-powered security, log correlation engine, open source threat detection</sub>

## RAG Memory (Qdrant)

SOC Beacon can use Qdrant-backed retrieval augmented generation (RAG) during AI enrichment.
Before scoring an alert as `malicious` or `false_positive`, it retrieves similar previously labeled alerts and adds them to model context.

Environment variables:
- `QDRANT_URL` (required to enable Qdrant retrieval)
- `QDRANT_API_KEY` (optional)
- `QDRANT_COLLECTION` (optional, default `soc_beacon_alert_memory`)
- `RAG_EMBEDDING_MODEL` (optional, default `text-embedding-3-small`)

If Qdrant is unavailable, SOC Beacon falls back to local historical labeled alerts from the embedded database.

### Docker Production (App + Qdrant)

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

This starts:
- `soc-beacon` on port `3000`
- `qdrant` on ports `6333` and `6334`
