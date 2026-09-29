# edr_agent.py
# Lightweight EDR Agent - FastAPI Application
# Author: Mary Chiamaka Ekwughaonu (U21CYS1048)
# Project: Developed Lightweight Endpoint Detection and Response Prototype
#          Using Machine Learning for Efficient Threat Detection and Prioritization

import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'   # Disable oneDNN for TensorFlow compatibility

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
import logging
import threading
import time
import json
import shutil
from datetime import datetime
from pathlib import Path

# Third-party
from elasticsearch import Elasticsearch
import joblib
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
import schedule
import tailer
import subprocess
import requests

# ====================== CONFIGURATION ======================
BASE_DIR = Path(r"C:\Users\HP\Desktop\EDR-PROTOTYPE")
LOG_DIR = BASE_DIR / "backend" / "logs"
ARCHIVE_DIR = LOG_DIR / "archive"
MODELS_DIR = BASE_DIR / "models"
FRONTEND_DIR = BASE_DIR / "edr-frontend"

ELASTICSEARCH_HOST = "localhost"
ELASTICSEARCH_PORT = 9200
ALIAS_NAME = "edr-logs"
BEAT_INDICES = [".ds-packetbeat-*", ".ds-winlogbeat-*"]

# Create directories if they don't exist
LOG_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

# ====================== LOGGING ======================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("EDR-Agent")

# ====================== ELASTICSEARCH ======================
es_client = Elasticsearch(
    hosts=[{"host": ELASTICSEARCH_HOST, "port": ELASTICSEARCH_PORT, "scheme": "http"}],
    request_timeout=60,
    max_retries=5,
    retry_on_timeout=True
)

def setup_elasticsearch_template():
    """Create index template for Beats data (Packetbeat & Winlogbeat)"""
    if not es_client.ping():
        logger.warning("Elasticsearch is not available")
        return

    template_body = {
        "index_patterns": BEAT_INDICES,
        "template": {
            "aliases": {ALIAS_NAME: {}},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "timestamp": {"type": "date"},
                    "source.ip": {"type": "ip"},
                    "destination.ip": {"type": "ip"},
                    "host.ip": {"type": "ip"},
                    "winlog.event_id": {"type": "keyword"},
                    "event.action": {"type": "keyword"},
                    "process.name": {"type": "keyword"},
                    "anomaly_score": {"type": "float"},
                    "is_malicious": {"type": "boolean"},
                    "prediction_model": {"type": "keyword"}
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            }
        }
    }

    try:
        es_client.indices.put_index_template(name="edr-logs-template", body=template_body)
        logger.info("Elasticsearch index template created successfully")
    except Exception as e:
        logger.error(f"Failed to create index template: {e}")

# ====================== LOG MANAGEMENT ======================
def get_latest_log_files():
    """Dynamically discover the latest log files"""
    base_dirs = {
        "packetbeat": BASE_DIR / "backend" / "tools" / "packetbeat-9.0.2-windows-x86_64" / "packetbeat-9.0.2" / "logs",
        "winlogbeat": BASE_DIR / "backend" / "tools" / "Winlogbeat" / "logs",
        "sysmon": LOG_DIR
    }

    log_files = []
    for name, dir_path in base_dirs.items():
        if dir_path.exists():
            files = list(dir_path.glob(f"{name}*.ndjson")) + list(dir_path.glob(f"{name}*.json"))
            if files:
                latest = max(files, key=lambda x: x.stat().st_mtime)
                log_files.append(str(latest))
                logger.info(f"Monitoring latest {name} log: {latest.name}")
    return log_files

def rotate_logs(log_files):
    """Rotate logs larger than 10MB"""
    for log_file in log_files:
        path = Path(log_file)
        if path.exists() and path.stat().st_size > 10 * 1024 * 1024:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = ARCHIVE_DIR / f"{path.stem}_{timestamp}{path.suffix}"
            shutil.move(str(path), str(dest))
            path.touch()  # create empty new file
            logger.info(f"Rotated log: {path.name} → {dest.name}")

def delete_old_logs():
    """Delete archived logs older than 7 days"""
    cutoff = time.time() - (7 * 24 * 60 * 60)
    for file in ARCHIVE_DIR.iterdir():
        if file.is_file() and file.stat().st_mtime < cutoff:
            file.unlink()
            logger.info(f"Deleted old archive: {file.name}")

def run_log_management_scheduler(log_files):
    schedule.every().day.at("00:00").do(rotate_logs, log_files)
    schedule.every().sunday.at("00:00").do(delete_old_logs)
    while True:
        schedule.run_pending()
        time.sleep(60)

# ====================== MACHINE LEARNING MODELS ======================
cnn_model_h5 = None
cnn_model_keras = None
rf_model = None
tflite_interpreter = None
tflite_available = False

def load_models():
    global cnn_model_h5, cnn_model_keras, rf_model, tflite_interpreter, tflite_available

    try:
        cnn_model_h5 = load_model(MODELS_DIR / "cnn_endpoint_logs.h5")
        logger.info("Loaded CNN (.h5) model")
    except Exception as e:
        logger.error(f"Failed to load CNN .h5 model: {e}")

    try:
        cnn_model_keras = load_model(MODELS_DIR / "cnn_endpoint_logs.keras")
        logger.info("Loaded CNN (.keras) model")
    except Exception as e:
        logger.error(f"Failed to load CNN .keras model: {e}")

    try:
        rf_model = joblib.load(MODELS_DIR / "rf_cicids2017_model.joblib")
        logger.info("Loaded Random Forest model")
    except Exception as e:
        logger.error(f"Failed to load Random Forest model: {e}")

    try:
        from ai_edge_litert.interpreter import Interpreter
        tflite_interpreter = Interpreter(model_path=str(MODELS_DIR / "cnn_endpoint_logs_quant.tflite"))
        tflite_interpreter.allocate_tensors()
        tflite_available = True
        logger.info("Loaded TFLite model")
    except Exception as e:
        logger.warning(f"TFLite model not available: {e}")

# ====================== LOG PROCESSING ======================
def normalize_log_entry(log_entry: dict) -> dict:
    """Normalize different log formats into a standard structure"""
    normalized = {
        "@timestamp": log_entry.get("@timestamp") or datetime.utcnow().isoformat() + "Z",
        "timestamp": log_entry.get("@timestamp") or datetime.utcnow().isoformat() + "Z",
        "raw_log": log_entry
    }

    # Winlogbeat / Sysmon
    if "winlog" in log_entry:
        winlog = log_entry["winlog"]
        normalized.update({
            "event_id": winlog.get("event_id"),
            "process_name": winlog.get("provider_name") or winlog.get("event_data", {}).get("Image"),
            "command_line": winlog.get("event_data", {}).get("CommandLine"),
            "source_ip": log_entry.get("host", {}).get("ip")
        })

    # Packetbeat
    elif log_entry.get("event", {}).get("category") == "network":
        normalized.update({
            "event_id": f"netflow-{hash(str(log_entry))}",
            "source_ip": log_entry.get("source", {}).get("ip"),
            "dest_ip": log_entry.get("destination", {}).get("ip"),
            "process_name": "network_flow"
        })

    return normalized

def predict_log(log_dict: dict) -> dict:
    """Predict anomaly using available models (ensemble when possible)"""
    try:
        # Endpoint log (process + command line)
        if any(k in log_dict for k in ["process_name", "command_line"]):
            df = pd.DataFrame([{
                "process_name": str(log_dict.get("process_name", "unknown")),
                "command_line": str(log_dict.get("command_line", "none"))
            }])
            df["process_name"] = df["process_name"].astype("category").cat.codes
            df["command_line"] = df["command_line"].astype("category").cat.codes
            input_data = df[["process_name", "command_line"]].values.astype(np.float32)

            scores = []
            if cnn_model_h5 is not None:
                scores.append(float(cnn_model_h5.predict(input_data, verbose=0)[0, 0]))
            if cnn_model_keras is not None:
                scores.append(float(cnn_model_keras.predict(input_data, verbose=0)[0, 0]))
            if tflite_available:
                input_details = tflite_interpreter.get_input_details()
                output_details = tflite_interpreter.get_output_details()
                tflite_interpreter.set_tensor(input_details[0]["index"], input_data)
                tflite_interpreter.invoke()
                scores.append(float(tflite_interpreter.get_tensor(output_details[0]["index"])[0, 0]))

            anomaly_score = float(np.mean(scores)) if scores else 0.0
            return {
                "anomaly_score": anomaly_score,
                "is_malicious": anomaly_score > 0.5,
                "prediction_model": "ensemble" if len(scores) > 1 else "cnn"
            }

        # Network log (source + dest IP)
        elif any(k in log_dict for k in ["source_ip", "dest_ip"]):
            def ip_to_int(ip):
                try:
                    return sum(int(octet) * 256 ** i for i, octet in enumerate(reversed(ip.split("."))))
                except:
                    return 0

            df = pd.DataFrame([{
                "source_ip": ip_to_int(log_dict.get("source_ip", "0.0.0.0")),
                "dest_ip": ip_to_int(log_dict.get("dest_ip", "0.0.0.0"))
            }])
            input_data = df.values

            if rf_model is not None:
                score = float(rf_model.predict_proba(input_data)[0, 1])
                return {
                    "anomaly_score": score,
                    "is_malicious": score > 0.5,
                    "prediction_model": "random_forest"
                }

        return {"anomaly_score": 0.0, "is_malicious": False, "prediction_model": "none"}

    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return {"anomaly_score": 0.0, "is_malicious": False, "prediction_model": "error"}

def process_log_entry(log_entry: dict):
    """Full processing pipeline"""
    try:
        normalized = normalize_log_entry(log_entry)
        prediction = predict_log(normalized)
        normalized.update(prediction)

        # Index into Elasticsearch
        if es_client.ping():
            es_client.index(index=ALIAS_NAME, document=normalized)

        # Save malicious threats locally
        if prediction.get("is_malicious"):
            threat_file = LOG_DIR / "detected_threats.json"
            with open(threat_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(normalized) + "\n")
            logger.warning(f"Malicious activity detected: {normalized.get('event_id')}")

        return normalized
    except Exception as e:
        logger.error(f"Error processing log: {e}")
        return None

def tail_log_files(log_files):
    """Real-time log tailing agent"""
    while True:
        for log_file in log_files:
            if not Path(log_file).exists():
                continue
            try:
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in tailer.follow(f):
                        try:
                            entry = json.loads(line.strip())
                            process_log_entry(entry)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.error(f"Error tailing {log_file}: {e}")
        time.sleep(5)

# ====================== API MODELS ======================
class LogEntry(BaseModel):
    timestamp: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    event_id: int | str | None = None
    process_name: str | None = None
    command_line: str | None = None

# ====================== LIFESPAN & BACKGROUND TASKS ======================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting EDR Agent...")
    setup_elasticsearch_template()
    load_models()

    log_files = get_latest_log_files()

    # Start background agents
    threading.Thread(target=tail_log_files, args=(log_files,), daemon=True).start()
    threading.Thread(target=run_log_management_scheduler, args=(log_files,), daemon=True).start()

    # Generate some test events
    try:
        subprocess.run("wevtutil qe System /rd:true /c:1 /f:text", shell=True, check=False)
        requests.get("https://www.google.com", timeout=3)
        logger.info("Generated test events")
    except Exception:
        pass

    logger.info("EDR Agent is fully operational")
    yield
    logger.info("EDR Agent shutting down")

# ====================== FASTAPI APPLICATION ======================
app = FastAPI(title="Lightweight EDR Agent", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/logs")
async def receive_log(log: LogEntry):
    result = process_log_entry(log.model_dump(exclude_unset=True))
    return {"status": "success", "prediction": result}

@app.get("/api/threats")
async def get_threats(size: int = 50):
    if not es_client.ping():
        raise HTTPException(status_code=503, detail="Elasticsearch unavailable")

    response = es_client.search(
        index=ALIAS_NAME,
        body={
            "query": {"match_all": {}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": size
        }
    )
    threats = [hit["_source"] for hit in response["hits"]["hits"]]
    return {"status": "success", "count": len(threats), "threats": threats}

@app.get("/api/threats-test")
async def test_threats():
    return {
        "status": "success",
        "elasticsearch_connected": es_client.ping(),
        "models_loaded": {
            "cnn_h5": cnn_model_h5 is not None,
            "cnn_keras": cnn_model_keras is not None,
            "random_forest": rf_model is not None,
            "tflite": tflite_available
        }
    }

@app.get("/api/stats")
async def get_stats():
    threats_file = LOG_DIR / "detected_threats.json"
    threats = []
    if threats_file.exists():
        with open(threats_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    threats.append(json.loads(line.strip()))
                except:
                    continue

    total = len(threats)
    critical = sum(1 for t in threats if t.get("anomaly_score", 0) >= 0.8)
    high = sum(1 for t in threats if 0.5 <= t.get("anomaly_score", 0) < 0.8)
    medium = sum(1 for t in threats if 0.3 <= t.get("anomaly_score", 0) < 0.5)
    low = sum(1 for t in threats if t.get("anomaly_score", 0) < 0.3)

    return {
        "total_threats": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "last_updated": datetime.utcnow().isoformat() + "Z"
    }

# Serve frontend
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
