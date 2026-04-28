# AI DevOps Log Monitoring & Threat Detection System

A full-stack, containerized SecOps platform that uses Local LLMs (Ollama) to analyze DevOps logs for security threats in real-time.

## 🚀 Quick Start

1. **Prerequisites**: Ensure you have [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
2. **Clone the project**:
   ```bash
   git clone <repository-url>
   cd centralized_log_monitoring
   ```
3. **Launch the stack**:
   ```bash
   docker-compose up --build -d
   ```
4. **Access the Dashboard**: Open [http://localhost:8000](http://localhost:8000) in your browser.

> [!NOTE]
> On the first run, the system will automatically download the `llama3` model (approx. 4.7GB). This may take several minutes depending on your internet speed.

## 🏗️ Architecture

- **Elasticsearch**: Centralized storage for all ingested logs.
- **Filebeat**: High-performance log collector that monitors generated log files.
- **Ollama**: Local AI engine running `llama3` for private, off-grid log analysis.
- **Django Backend**: Orchestrates the analysis pipeline and provides a REST API.
- **SecOps Dashboard**: Premium dark-mode UI for real-time monitoring and threat patching.
- **Log Generator**: Python microservice that simulates realistic App, System, and Attack traffic.

## 🛠️ Key Features

- **Automated AI Audits**: Every minute, the system fetches recent logs and asks the AI to classify activity (NORMAL vs ATTACK).
- **Threat Patching**: Mark detected attacks as "RESOLVED" once you have patched the underlying issue.
- **Live Log Stream**: View raw data flowing from your services in real-time.
- **Risk Scoring**: AI provides a risk score (0-100) and a detailed explanation for every classification.
- **Memory Optimized**: Pre-configured with memory limits to run smoothly on standard development machines.

## 📊 Dashboard Access

| Service | URL | Credentials |
|---------|-----|-------------|
| **SecOps Dashboard** | [http://localhost:8000](http://localhost:8000) | N/A |
| **Elasticsearch API** | [http://localhost:9200](http://localhost:9200) | N/A |
| **Ollama API** | [http://localhost:11434](http://localhost:11434) | N/A |
| **Grafana** | [http://localhost:3000](http://localhost:3000) | admin / admin |

## 🔍 Troubleshooting

- **Logs not appearing?**: Wait about 30 seconds for Filebeat to establish its connection to Elasticsearch.
- **AI Analysis failing?**: Ensure your machine has at least 8GB of RAM available for the `llama3` model.
- **Permissions Error (Windows)**: The `docker-compose` file is pre-configured with `-strict.perms=false` to handle Windows filesystem mount limitations.

## 📜 Maintenance

To stop the system:
```bash
docker-compose down
```

To view real-time logs from the AI analysis service:
```bash
docker-compose logs -f django-app
```
