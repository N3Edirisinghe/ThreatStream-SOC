# Autonomous SOC Simulation Platform
> **University Capstone Project** — SIEM + SOAR + ML Anomaly Detection  
> *Production-style, open-source, runs locally via Docker Compose*

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61dafb)](https://react.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## 🚀 Quick Start (< 5 minutes)

```bash
# 1. Clone and configure
git clone https://github.com/YOUR_USERNAME/soc-platform.git
cd soc-platform
cp .env.example .env          # Edit .env with your secrets

# 2. Start infrastructure (first run pulls ~3GB of images)
docker-compose up -d zookeeper kafka redis postgres opensearch

# 3. Wait ~60s for services to be healthy, then start platform
docker-compose up -d ingestion-api parser detection-engine api-gateway

# 4. Launch frontend (dev mode, hot-reload)
cd frontend && npm install && npm run dev

# 5. Generate test data and ingest
python scripts/generate_synthetic_logs.py --count 10000 --attacks 50
python scripts/ingest_file.py data/sample_logs/synthetic_mixed.jsonl
```

Open **http://localhost:3000** → Login with `admin` / `Admin@SOC123!`

---

## 🏗 Architecture

```
Log Sources → [Ingestion API] → Kafka [raw.logs]
                                    ↓
                            [Parser/Normalizer] → OpenSearch + Kafka [normalized.logs]
                                    ↓
              ┌─────────────────────┼──────────────────────┐
              ↓                     ↓                      ↓
        [Rule Engine]       [Correlation Engine]    [ML Anomaly Engine]
              └─────────────────────┼──────────────────────┘
                             Kafka [alerts]
                                    ↓
                           [Enrichment Service]
                                    ↓
                           [SOAR Orchestrator] → PostgreSQL (incidents)
                                    ↓
                           [API Gateway] ← React Dashboard
```

See [Architecture Document](docs/architecture.md) for full detail.

---

## 📁 Repository Structure

```
soc-platform/
├── docker-compose.yml          # Full service orchestration
├── .env.example                # Environment template
├── services/
│   ├── ingestion/              # FastAPI — HTTP log ingest → Kafka
│   ├── parser/                 # Kafka consumer → ECS normalization → OpenSearch
│   ├── detection/              # Rule engine + Correlation engine
│   │   └── rules/              # JSON detection rules (det-001 … det-010)
│   ├── ml_engine/              # IsolationForest training + inference [Week 8]
│   ├── enrichment/             # GeoIP + AbuseIPDB + ATT&CK lookup [Week 6]
│   ├── soar/                   # Playbook engine + action handlers [Week 7]
│   └── api_gateway/            # FastAPI REST API (auth, alerts, incidents, metrics)
│       └── routers/            # auth.py | alerts.py | incidents.py | metrics.py | rules.py
├── frontend/                   # React 18 + Vite SOC dashboard
│   └── src/
│       ├── pages/              # Dashboard | Alerts | Incidents | Login
│       ├── hooks/useAuth.tsx   # JWT auth context
│       └── api/client.ts       # Axios API client
├── scripts/
│   ├── generate_synthetic_logs.py  # Generates test log data with planted attacks
│   └── sql/init_schema.sql         # PostgreSQL schema (auto-runs on first start)
├── data/sample_logs/           # Generated .jsonl files (gitignored)
├── models/                     # Trained ML model artifacts (gitignored)
└── docs/                       # Architecture, API, runbooks
```

---

## 🔑 Default Credentials

| Service | URL | Default Login |
|---------|-----|---------------|
| SOC Dashboard | http://localhost:3000 | admin / Admin@SOC123! |
| API Docs (Swagger) | http://localhost:8000/docs | — (use JWT) |
| OpenSearch Dashboards | http://localhost:5601 | — |
| PostgreSQL | localhost:5432 | soc_app / changeme123 |

> **⚠ Change all passwords before any non-local deployment.**

---

## 🧪 Testing

```bash
# Unit tests
cd services/detection && pip install pytest pytest-cov
pytest tests/ -v --cov=. --cov-report=term-missing

# Integration test — end-to-end brute force detection
python tests/integration/test_e2e_pipeline.py

# Attack simulation
python scripts/generate_synthetic_logs.py --attack-only --attacks 100 --out ./data/sample_logs/
```

---

## 📖 Documentation

- [Architecture & Data Flow](docs/architecture.md)
- [API Reference](http://localhost:8000/docs) (Swagger — live when running)
- [Detection Rule Library](services/detection/rules/)
- [SOC Runbooks](docs/runbooks/)

---

## 🗺 12-Week Roadmap

| Week | Milestone |
|------|-----------|
| 1–2  | Infrastructure + Ingestion + Parser |
| 3–4  | **MVP** — Rule engine + basic API + React shell |
| 5    | All 10 detection rules + Correlation engine |
| 6    | Enrichment service (GeoIP, TI) |
| 7    | SOAR playbooks + human approval flow |
| 8    | ML Anomaly Detection (IsolationForest) |
| 9–10 | Full dashboard + ATT&CK heatmap |
| 11   | Purple-team mode + Atomic Red Team testing |
| 12   | Demo polish + academic report |

---

## 🎓 Academic Research Questions

1. Does hybrid detection (rule + ML) achieve significantly higher F1 than rules alone?
2. What is the MTTD improvement with automated SOAR triage vs manual?
3. Does threat intel enrichment reduce analyst FP classification time?

---

## 📜 License

MIT — Free to use for academic and research purposes.
