<div align="center">
  <h1>🛡️ ThreatStream-SOC</h1>
  <p><strong>An Autonomous Security Operations Center (SOC) Simulation Platform</strong></p>
  <p><i>Real-time streaming threat detection powered by Kafka, Redis, and FastAPI</i></p>

  <p>
    <a href="#overview">Overview</a> •
    <a href="#features">Features</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#getting-started">Getting Started</a>
  </p>
</div>

---

## 📖 Overview

**ThreatStream-SOC** is a state-of-the-art, autonomous Security Operations Center simulation platform designed for real-time log ingestion, threat detection, and incident response. Built on a resilient microservices architecture, it seamlessly processes streaming data to identify malicious activities using both rule-based heuristics and stateful multi-step correlation logic.

## ✨ Features

- **🚀 Real-time Event Streaming:** Rapid log ingestion and normalization powered by **Apache Kafka**.
- **🧠 Advanced Detection Engines:**
  - **Rule-based Engine:** Single-event field matching against rigid security rules.
  - **Correlation Engine:** Stateful, multi-step event correlation via **Redis** to detect complex attack patterns over time.
- **⚡ High-Performance API:** Robust **FastAPI** gateway managing authentication, alerts, incidents, metrics, rules, and playbooks.
- **📊 Interactive Dashboard:** A dynamic, premium frontend for visualizing live threat feeds, alert statuses, and system metrics.
- **🐳 Containerized Microservices:** Fully dockerized ecosystem (`docker-compose`) ensuring seamless deployment and isolation of services.

## 🏗️ Architecture

The platform operates through a series of interconnected microservices:

1. **API Gateway (`FastAPI`)**: The central entry point for the frontend dashboard and external interactions.
2. **Detection Engine (`Python`)**: Consumes `normalized.logs` from Kafka, evaluates events against rules, and produces verified incidents to the `alerts` Kafka topic.
3. **Message Broker (`Kafka / Zookeeper`)**: Facilitates high-throughput, fault-tolerant communication between services.
4. **State Management (`Redis`)**: Maintains temporary state for multi-step correlation scenarios (e.g., repeated failed logins before success).
5. **Frontend Dashboard (`React/HTML`)**: Provides a real-time visualization layer for the SOC analysts.

## 🚀 Getting Started

### Prerequisites

- [Docker](https://www.docker.com/get-started) and [Docker Compose](https://docs.docker.com/compose/install/)
- Python 3.9+ (If running services locally outside of Docker)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/N3Edirisinghe/ThreatStream-SOC.git
   cd ThreatStream-SOC
   ```

2. **Start the platform using Docker Compose:**
   ```bash
   docker-compose up -d --build
   ```
   *This will spin up Kafka, Redis, the API Gateway, Detection Engine, and the Frontend.*

3. **Access the Dashboard:**
   Open your browser and navigate to `http://localhost:3000`.

4. **Access the API Documentation:**
   Interactive API docs are automatically generated and available at `http://localhost:8000/docs`.

## 📂 Project Structure

```text
ThreatStream-SOC/
├── frontend/                  # React/HTML dashboard application
├── services/
│   ├── api_gateway/           # FastAPI gateway and core REST endpoints
│   ├── detection/             # Python-based rule and correlation engine
│   └── parser/                # Log ingestion and normalization service
├── scripts/                   # Utility scripts (e.g., generate synthetic logs)
├── docker-compose.yml         # Container orchestration
└── README.md
```

## 📜 License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.
