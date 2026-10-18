"""ThreatLens Central Configuration Module."""

import os
import logging
from pathlib import Path

# Base Paths
SRC_DIR = Path(__file__).resolve().parent
BASE_DIR = SRC_DIR.parent
MODELS_DIR = BASE_DIR / "models"
ARTIFACTS_DIR = BASE_DIR / "artifacts"
DATA_DIR = BASE_DIR / "data"
DOCS_DIR = BASE_DIR / "docs"

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = DATA_DIR / "threatlens.db"

# Exact 20 Selected Features (Strict Training Order)
FEATURE_NAMES = [
    "numeric__Avg Packet Size",
    "numeric__Bwd Packet Length Mean",
    "numeric__Avg Bwd Segment Size",
    "numeric__Subflow Bwd Bytes",
    "numeric__Bwd Packets Length Total",
    "numeric__Packet Length Mean",
    "numeric__Packet Length Std",
    "numeric__Packet Length Variance",
    "numeric__Packet Length Max",
    "numeric__Bwd Packet Length Max",
    "numeric__Subflow Fwd Bytes",
    "numeric__Fwd Packets Length Total",
    "numeric__Bwd Packet Length Std",
    "numeric__Fwd Packet Length Max",
    "numeric__Init Bwd Win Bytes",
    "numeric__Fwd IAT Max",
    "numeric__Init Fwd Win Bytes",
    "numeric__Fwd IAT Total",
    "numeric__Flow IAT Max",
    "numeric__Fwd IAT Mean",
]

# 15 Class Names Mapping (Index -> Name)
CLASS_NAMES = {
    0: "Benign",
    1: "Bot",
    2: "DDoS",
    3: "DoS GoldenEye",
    4: "DoS Hulk",
    5: "DoS Slowhttptest",
    6: "DoS slowloris",
    7: "FTP-Patator",
    8: "Heartbleed",
    9: "Infiltration",
    10: "PortScan",
    11: "SSH-Patator",
    12: "Web Attack Brute Force",
    13: "Web Attack Sql Injection",
    14: "Web Attack XSS",
}

# Reverse Mapping (Name -> Index)
CLASS_TO_INDEX = {name: idx for idx, name in CLASS_NAMES.items()}

# Threat Category & Severity Mappings
SEVERITY_LEVELS = {
    "Benign": "Low",
    "Bot": "High",
    "DDoS": "Critical",
    "DoS GoldenEye": "High",
    "DoS Hulk": "High",
    "DoS Slowhttptest": "Medium",
    "DoS slowloris": "High",
    "FTP-Patator": "High",
    "Heartbleed": "Critical",
    "Infiltration": "Critical",
    "PortScan": "Medium",
    "SSH-Patator": "High",
    "Web Attack Brute Force": "High",
    "Web Attack Sql Injection": "Critical",
    "Web Attack XSS": "Medium",
}

SEVERITY_COLORS = {
    "Low": "#10B981",       # Emerald Green
    "Medium": "#F59E0B",    # Amber Yellow
    "High": "#F97316",      # Orange
    "Critical": "#EF4444",  # Crimson Red
}

THREAT_CATEGORIES = {
    "Benign": "Normal Traffic",
    "Bot": "Botnet Activity",
    "DDoS": "Denial of Service",
    "DoS GoldenEye": "Denial of Service",
    "DoS Hulk": "Denial of Service",
    "DoS Slowhttptest": "Denial of Service",
    "DoS slowloris": "Denial of Service",
    "FTP-Patator": "Brute Force Authentication",
    "SSH-Patator": "Brute Force Authentication",
    "Heartbleed": "Exploit / Vulnerability",
    "Infiltration": "Network Infiltration",
    "PortScan": "Reconnaissance / Probe",
    "Web Attack Brute Force": "Web Attack",
    "Web Attack Sql Injection": "Web Attack",
    "Web Attack XSS": "Web Attack",
}

# Empirical Outlier Rule Thresholds (Task 9 Discovery)
RULE_THRESHOLDS = {
    "numeric__Avg Packet Size": 1.126,
    "numeric__Bwd Packet Length Mean": 0.8752,
    "numeric__Avg Bwd Segment Size": 0.8752,
    "numeric__Subflow Bwd Bytes": -0.004224,
    "numeric__Bwd Packets Length Total": -0.004224,
    "numeric__Packet Length Mean": 1.148,
    "numeric__Packet Length Variance": -0.02321,
    "numeric__Packet Length Max": 1.41,
    "numeric__Bwd Packet Length Max": 1.503,
    "numeric__Subflow Fwd Bytes": 0.02992,
    "numeric__Fwd Packets Length Total": 0.02987,
    "numeric__Fwd Packet Length Max": 0.7736,
    "numeric__Fwd IAT Total": -0.02986,
    "numeric__Fwd IAT Mean": 0.01794,
    "numeric__Init Fwd Win Bytes": 1.159,
    "numeric__Init Bwd Win Bytes": -0.1653,
    "numeric__Fwd IAT Max": 0.1803,
    "numeric__Flow IAT Max": 0.2054,
    "numeric__Packet Length Std": 1.378,
    "numeric__Bwd Packet Length Std": 1.143,
}

# Model Filenames
MODEL_FILES = {
    "logistic_regression": MODELS_DIR / "logistic_regression.joblib",
    "decision_tree": MODELS_DIR / "decision_tree.joblib",
    "random_forest": MODELS_DIR / "random_forest.joblib",
    "lstm": MODELS_DIR / "ThreatLens_LSTM_Model.keras",
}

def setup_logger(name: str = "threatlens") -> logging.Logger:
    """Configures and returns a structured logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    return logger
