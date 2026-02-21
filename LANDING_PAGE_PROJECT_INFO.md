# SOC Beacon Project Description

## Product Overview
SOC Beacon is a lightweight Security Operations Center (SOC) platform for ingesting logs, generating alerts, enriching incidents with AI and threat intelligence, and managing triage workflows in one dashboard.

It is designed for teams that need practical detection and response workflows without the overhead of a large SIEM deployment. The platform accepts logs through API/syslog, converts them into actionable alerts, and adds investigation context automatically.

## Core Value Proposition
- Centralize security event ingestion and alert triage.
- Automatically enrich alerts with AI analysis and external threat intelligence.
- Keep analysts focused with verdict/status workflows and detailed alert views.
- Provide usable SOC capabilities with cost-aware AI defaults.

## Primary Users
- SOC analysts handling daily investigation queues.
- Security engineers building detection and enrichment pipelines.
- Blue teams in SMB/mid-size environments needing fast deployment.
- Security consultants running incident monitoring for clients.

## Key Product Capabilities

### 1. Log Ingestion
- REST API ingestion endpoint (`/api/v1/logs`) with API key support.
- Batch and single-log ingestion.
- Parsing/normalization from raw messages into structured records.
- Severity handling from provided or inferred values.
- Per-log alert generation pipeline.

### 2. Alert Generation and Classification
- Alerts include title, description, severity, source, source/destination IP, MITRE mapping, and raw log.
- Severity can be recategorized after enrichment.
- Alert model includes:
  - `verdict`: `malicious | suspicious | false_positive`
  - `incidentStatus`: `unassigned | in_progress | resolved`

### 3. AI Enrichment (OpenAI)
- OpenAI-only provider configuration in settings.
- Cheap-default model support (default set to `gpt-4.1-nano`).
- Multi-agent analysis (configurable 1-4 calls per alert) with different analyst perspectives.
- AI output influences verdict and incident escalation logic.
- Cost-sensitive controls:
  - agent count
  - max tokens
  - temperature
  - auto-enrich toggle

### 4. Scoring
- Per-alert scoring includes:
  - `AI Score`
  - `Heuristics Score`
- Both displayed in circular visual indicators in list and detail views.
- Risk visual mapping:
  - high score = red (higher risk)
  - medium = amber
  - low = green

### 5. Threat Intelligence Enrichment
- Built-in no-key enrichment support from open sources (for IPs/domains/URLs/hashes).
- Key-based external feed support configurable in settings.
- Threat intel context is attached to alert enrichment for analyst review.

### 6. Detection Engines
- YARA rule support with on/off toggles for rules.
- Sigma support with configurable path and max rules loading.
- Sigma integration is settings-configurable and used during ingestion classification.

### 7. Analyst Workflow and Case Handling
- Alert list with filters, search, status control, and verdict management.
- Alert detail view with tabbed investigation context (AI analysis, MITRE, enrichment, raw log).
- Manual updates for verdict and incident status.
- Alert deletion from detail view.
- Two timestamps shown per alert:
  - event/alert time
  - ingested time

### 8. Alerts Table UX
- Sortable alert table columns.
- Toggleable visible columns.
- Score columns for AI/Heuristics with ring visuals.
- Fast scanning layout for high-volume operations.

### 9. Platform Settings and Operations
- Settings tabs for:
  - General
  - Ingestion (API/syslog)
  - AI/LLM
  - YARA
  - Sigma
  - Output
  - Threat Intel
  - Authentication
  - Help
- Built-in API usage examples.

## Technical Architecture

### Frontend
- Next.js App Router.
- React client components for interactive dashboard actions.
- Tailwind-based design system and reusable UI components.

### Backend
- Next.js server routes + server actions.
- Ingestion and enrichment orchestration in library modules.
- SQL.js-backed local database persisted to disk.

### Data Domains
- Logs
- Alerts
- Alert enrichments
- Threat feeds
- YARA rules
- Settings
- Users/auth

## End-to-End Workflow
1. A log arrives through API or other ingestion source.
2. Parser/classifier normalizes event and determines initial severity/mapping.
3. Alert is created with baseline metadata.
4. Threat intel enrichment runs to collect IOC context.
5. AI enrichment runs (if enabled/configured), producing analysis and score.
6. Alert fields update:
   - score data
   - verdict
   - potential incident escalation
   - optional severity recataloging
7. Analyst reviews alert in the dashboard and updates incident workflow as needed.

## Product Positioning
SOC Beacon is positioned as a practical SOC operations layer between raw log collection and full enterprise SIEM complexity. It emphasizes:
- speed to value
- analyst usability
- enrichment depth
- low-cost AI usage
- configurable detection logic (YARA/Sigma)

## Current Maturity Snapshot
- Functional feature set across ingestion, detection, enrichment, and triage.
- Strong prototype-to-production trajectory.
- Suitable for security labs, SMB SOC teams, and pilot deployments.
- Ongoing hardening areas include deeper testing, typecheck cleanup, and advanced Sigma engine fidelity.
