# Lightweight EDR Agent

**Project Title:** Developed Lightweight Endpoint Detection and Response Prototype Using Machine Learning for Efficient Threat Detection and Prioritization  

**Author:** Mary Chiamaka Ekwughaonu
**Institution:** Air Force Institute of Technology, Kaduna  
**Department:** Cyber Security  

---

## Overview

This is an autonomous **EDR Agent** built with FastAPI. It continuously monitors endpoint and network logs, detects threats using machine learning models, prioritizes them, stores results in Elasticsearch, and serves a web frontend dashboard.

---

## Functionalities

### 1. FastAPI Application
- Creates a web server using FastAPI to handle log ingestion and serve a frontend interface.

### 2. Elasticsearch Integration
- Connects to Elasticsearch for log storage and querying
- Sets up index templates for Beats data (Packetbeat, Winlogbeat)
- Normalizes and indexes log entries from different sources

### 3. Log Management
- Monitors system logs (Sysmon, Packetbeat, Winlogbeat)
- Implements log rotation (files larger than 10MB)
- Implements log cleanup (archives older than 7 days)
- Dynamically discovers the latest log files
- Tails log files in real-time for continuous processing

### 4. Machine Learning Models
- Loads multiple ML models:
  - CNN (`.h5` format)
  - CNN (`.keras` format)
  - Random Forest (`.joblib`)
  - Quantized TFLite model
- Disables oneDNN optimizations for TensorFlow compatibility
- Predicts anomalies based on:
  - Process names and command lines (endpoint logs)
  - Source and destination IP addresses (network logs)
- Combines predictions from multiple models for ensemble results

### 5. Log Processing
- Normalizes log formats from different sources (Winlogbeat, Packetbeat, Sysmon)
- Predicts malicious activity using ML models
- Stores detected threats and their anomaly scores
- Indexes processed logs in Elasticsearch

### 6. API Endpoints
| Endpoint              | Method | Description                                      |
|-----------------------|--------|--------------------------------------------------|
| `/logs`               | POST   | Receives and processes log entries               |
| `/api/threats`        | GET    | Retrieves recent threats from Elasticsearch      |
| `/api/threats-test`   | GET    | Tests Elasticsearch connectivity and model status|
| `/api/stats`          | GET    | Provides threat statistics (critical/high/medium/low) |

### 7. Background Tasks
- Runs log file tailing in a separate background thread
- Runs log management scheduler (rotation + cleanup) in a separate thread
- Generates test events for system monitoring during startup

### 8. Static File Serving
- Serves frontend files and static assets
- Mounts the frontend directory for web interface access

---

## Project Structure

```
EDR-PROTOTYPE/
├── backend/
│   ├── edr_agent.py          ← Main Agent application
│   ├── logs/                 ← Log storage & detected threats
│   └── tools/
│       ├── packetbeat-.../   ← Packetbeat logs
│       └── Winlogbeat/       ← Winlogbeat logs
├── models/
│   ├── cnn_endpoint_logs.h5
│   ├── cnn_endpoint_logs.keras
│   ├── cnn_endpoint_logs_quant.tflite
│   └── rf_cicids2017_model.joblib
└── edr-frontend/             ← Frontend dashboard
```

---

## Prerequisites

- Python 3.10 or higher
- Elasticsearch running on `localhost:9200`
- Winlogbeat and Packetbeat generating logs
- Docker Desktop (for Elasticsearch & Kibana)
- Required Python packages (see below)

---

## Installation

1. **Clone or copy the project** to:
   ```
   C:\Users\HP\Desktop\EDR-PROTOTYPE
   ```

2. **Install Python dependencies:**
   ```bash
   pip install fastapi uvicorn elasticsearch tensorflow joblib pandas numpy schedule tailer requests
   ```

3. **Ensure Elasticsearch is running** (via Docker Desktop):
   ```bash
   docker ps
   ```
   You should see the `elasticsearch` container running on port 9200.

4. **Place the trained models** in the `models/` folder:
   - `cnn_endpoint_logs.h5`
   - `cnn_endpoint_logs.keras`
   - `cnn_endpoint_logs_quant.tflite`
   - `rf_cicids2017_model.joblib`

---

## How to Run

1. Open a terminal and navigate to the backend directory:
   ```bash
   cd C:\Users\HP\Desktop\EDR-PROTOTYPE\backend
   ```

2. Start the EDR Agent:
   ```bash
   uvicorn edr_agent:app --host 0.0.0.0 --port 8000 --reload
   ```

3. Open your browser and visit:
   - **Frontend Dashboard:** http://localhost:8000
   - **API Docs (Swagger):** http://localhost:8000/docs
   - **Threats API:** http://localhost:8000/api/threats
   - **Stats API:** http://localhost:8000/api/stats
   - **Health Check:** http://localhost:8000/api/threats-test

---

## API Usage Examples

### Send a log entry
```bash
curl -X POST http://localhost:8000/logs \
  -H "Content-Type: application/json" \
  -d '{"process_name": "powershell.exe", "command_line": "Invoke-Mimikatz"}'
```

### Get recent threats
```bash
curl http://localhost:8000/api/threats?size=10
```

### Get statistics
```bash
curl http://localhost:8000/api/stats
```

---

## Notes
The original trained model files were lost after a system failure. The full architecture, agent design, data pipeline, and source code are preserved and documented in this repository.

- The agent automatically discovers the latest Packetbeat and Winlogbeat log files.
- Detected threats are saved to `backend/logs/detected_threats.json`.
- Logs larger than 10MB are rotated daily.
- Archives older than 7 days are automatically deleted.
- The agent runs background threads for continuous monitoring.

---

## Author

**Mary Chiamaka Ekwughaonu**  
Department of Cyber Security  
Air Force Institute of Technology, Kaduna  
August 2025
