# 🛡️ ThreatLens — Cybersecurity Log Decision-Support System

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.55.0-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Keras 3](https://img.shields.io/badge/Keras-3.12-D00000?logo=keras&logoColor=white)](https://keras.io/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.7-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?logo=sqlite&logoColor=white)](https://sqlite.org/)
[![Tests](https://img.shields.io/badge/Tests-11%20Passed-10B981?logo=pytest&logoColor=white)](https://pytest.org/)

**ThreatLens** is an AI-powered cybersecurity log analysis and decision-support web application. Designed for Security Operations Center (SOC) analysts and small-to-medium organizations, ThreatLens combines **rule-based expert reasoning**, **traditional machine learning** (Logistic Regression, Decision Tree, Random Forest), and **deep learning** (LSTM Neural Network) to detect, classify, and explain network security anomalies and cyber threats with high accuracy and transparent reasoning.

---

## 🌟 Key Application Features

- **🌐 SOC Executive Dashboard:** Real-time visibility into historical analysis metrics, monitored threat scope, live model readiness indicators, and security event categorization.
- **🔍 Log Triage & Validation:** Robust CSV validator that maps and normalizes 20 essential network traffic flow features, detects missing fields, imputes anomalies, and isolates ground-truth labels.
- **⚡ 1-Click Sample Testing:** Built-in 500-sample test log dataset (`artifacts/sample_test_logs.csv`) for immediate evaluation without requiring massive external datasets.
- **🤖 Quad-Model Unified Inference:** Parallel inference across:
  - **Logistic Regression** (Linear baseline)
  - **Decision Tree** (Interpretable tree structure)
  - **Random Forest** (High-accuracy ensemble)
  - **LSTM Neural Network** (Sequential deep learning over 3D tensors)
- **⚖️ Rule-Based AI Engine:** Isolated empirical statistical outlier detection ($Q_3 + 1.5 \times IQR$) providing explicit rule evidence strings (`R-OUTLIER`).
- **🎯 Task 9 Consensus Decision Pipeline:** Plurality voting with tie-breaking, disagreement escalation, consensus threshold verification ($\ge 75\%$), and actionable SOC response guidance.
- **🔬 Explainability & Local Reasoning:** Interactive drilldown into individual security events displaying feature deviation bars against training anomaly thresholds and model vote breakdowns.
- **📊 Task 10 Evaluation & Benchmarks:** Comprehensive accuracy, precision, recall, and F1 comparisons across models, plus dynamic evaluation when ground-truth labels are uploaded.
- **📜 Persistent Audit History:** Embedded SQLite database tracking scan timestamps, file identifiers, record counts, alert rates, and threat breakdowns.
- **📑 Multi-Format Export:** Instant downloads for enriched decision CSV files and executive-ready security audit PDF reports generated via ReportLab.

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────┐
│  Raw Network Security Log CSV                          │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│  1. Preprocessing & 20-Feature Normalization           │
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
               ▼                          ▼
┌───────────────────────────┐  ┌─────────────────────────┐
│ 2. Isolated Rule Engine   │  │ 3. Multi-Model Inference│
│    (R-OUTLIER Statistics) │  │    • Logistic Regression│
└──────────────┬────────────┘  │    • Decision Tree      │
               │               │    • Random Forest      │
               │               │    • LSTM Deep Learning │
               │               └──────────┬──────────────┘
               │                          │
               ▼                          ▼
┌────────────────────────────────────────────────────────┐
│  4. Task 9 Consensus & Decision Engine                 │
│     • Multi-Model Agreement Tally                      │
│     • Tie-Breaking & Disagreement Escalation           │
│     • Evidence-Based Explanation & Action Guidance     │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│  5. Actionable SOC Decision & Audit Reporting          │
│     • Real-time Streamlit Dashboard                    │
│     • SQLite Persistent Scan Database                  │
│     • Executive PDF & Enriched CSV Reports             │
└────────────────────────────────────────────────────────┘
```

---

## 📂 Repository Structure

```
ThreatLens/
├── app/
│   ├── main.py                     # Primary Streamlit web application & router
│   └── styles.py                   # Custom cybersecurity CSS & styled components
├── src/
│   ├── __init__.py                 # ThreatLens package initializer
│   ├── config.py                   # Central constants, paths, thresholds & class mappings
│   ├── preprocessing.py            # CSV schema validation & feature normalization
│   ├── model_loader.py             # Model loading & Keras 3.12 compatibility patch
│   ├── predict.py                  # Unified inference engine across all 4 models
│   ├── rules.py                    # Empirical outlier rule-based AI engine
│   ├── decision_engine.py          # Task 9 consensus, tie-breaking & explanation logic
│   ├── explain.py                  # Feature importance & local reasoning drilldown
│   ├── evaluation.py               # Benchmark comparison & dynamic evaluation
│   ├── database.py                 # SQLite persistence layer for scan history
│   └── reports.py                  # Executive PDF report & CSV export generators
├── models/
│   ├── logistic_regression.joblib  # Trained Logistic Regression model (4.3 KB)
│   ├── decision_tree.joblib        # Trained Decision Tree model (985 KB)
│   ├── ThreatLens_LSTM_Model.keras # Trained Keras LSTM deep learning model (325 KB)
│   └── random_forest.joblib        # Trained Random Forest model (106.3 MB, kept locally)
├── artifacts/
│   ├── sample_test_logs.csv        # 500 validated test records for instant demo
│   ├── ThreatLens_Feature_Metadata.csv
│   ├── ThreatLens_Feature_Importance.csv
│   ├── ThreatLens_Model_Evaluation.csv
│   ├── ThreatLens_LSTM_Evaluation.csv
│   ├── ThreatLens_Task9_Model_Comparison.csv
│   ├── ThreatLens_Error_Summary.csv
│   ├── ThreatLens_Error_Pattern_Comparison.csv
│   ├── ThreatLens_DecisionTree_Misclassifications.csv
│   ├── ThreatLens_Logistic_Misclassifications.csv
│   ├── ThreatLens_RandomForest_Misclassifications.csv
│   └── ThreatLens_Ontology.owl     # Protégé OWL ontology of classes and relations
├── notebooks/
│   ├── ThreatLens_Task2_Rule_Engine.ipynb                          # Task 2: Rule-Based Expert System (Forward Chaining)
│   ├── ThreatLens_Task3_State_Space_Search_Colab_Completed.ipynb   # Task 3: State-Space Search (BFS, DFS, A* Heuristic)
│   ├── ThreatLens_Task4_Complete.ipynb                             # Task 4: EDA, Cleaning, Deduplication & Preprocessing
│   ├── ThreatLens_Task5_Feature_Engineering.ipynb                  # Task 5: Feature Extraction & Top 20 Feature Selection
│   ├── CIL_TASK6.ipynb                                             # Task 6: ML Classifiers (LR, DT, RF Training & Eval)
│   ├── CIL_TASK7.ipynb                                             # Task 7: LSTM Deep Learning Architecture & Training
│   ├── CIL_TASK8.ipynb                                             # Task 8: LSTM Evaluation, Activations & Error Patterns
│   └── CIL_task9.ipynb                                             # Task 9: Multi-Model Consensus & Decision Engine
├── tests/
│   ├── test_preprocessing.py       # Input validation & missing feature tests
│   ├── test_model_loader.py        # Model loading & status tests
│   ├── test_predict.py             # Inference pipeline tests on sample data
│   ├── test_rules_decision.py      # Threshold rules & consensus logic tests
│   └── test_database_reports.py    # SQLite CRUD & PDF generation tests
├── docs/
│   ├── PROJECT_AUDIT.md            # Complete audit of academic artifacts & findings
│   ├── IMPLEMENTATION_PLAN.md      # Detailed phase breakdown & acceptance criteria
│   └── SESSION_HANDOFF.md          # State handoff guide for subsequent sessions
├── data/                           # Local SQLite database (`threatlens.db`)
├── .streamlit/
│   └── config.toml                 # Streamlit server & cybersecurity dark theme config
├── requirements.txt                # Pinned production dependencies
├── .gitignore                      # Large files (>100MB) & cache exclusions
└── README.md                       # Master documentation
```

---

## 🎯 15 Threat Classes Monitored

| Code | Class Label Name | Threat Category | Severity |
|---|---|---|---|
| `0` | **Benign** | Normal Network Traffic | Low (Info) |
| `1` | **Bot** | Botnet Traffic / C2 Activity | High |
| `2` | **DDoS** | Distributed Denial of Service | Critical |
| `3` | **DoS GoldenEye** | Denial of Service | High |
| `4` | **DoS Hulk** | Denial of Service | High |
| `5` | **DoS Slowhttptest** | Low & Slow HTTP Flooding | Medium |
| `6` | **DoS slowloris** | Denial of Service | High |
| `7` | **FTP-Patator** | FTP Brute Force Authentication | High |
| `8` | **Heartbleed** | Memory Disclosure Exploit | Critical |
| `9` | **Infiltration** | Internal Network Infiltration | Critical |
| `10` | **PortScan** | Reconnaissance / Network Probe | Medium |
| `11` | **SSH-Patator** | SSH Brute Force Authentication | High |
| `12` | **Web Attack Brute Force**| Web Application Credential Stuffing | High |
| `13` | **Web Attack Sql Injection**| SQL Injection Exploitation | Critical |
| `14` | **Web Attack XSS** | Cross-Site Scripting Injection | Medium |

---

## 🚀 Setup & Execution Guide (Windows)

### 1. Prerequisites
- **Python 3.10+** (64-bit recommended)
- **Git**

### 2. Clone the Repository
```powershell
git clone https://github.com/ryannorman0309/ThreatLens.git
cd ThreatLens
```

### 3. Create and Activate a Virtual Environment
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 4. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 5. Run Automated Tests
Verify your environment and model dependencies:
```powershell
python -m pytest -v
```
*(All 11 tests should pass in under 10 seconds).*

### 6. Launch the Streamlit Web Application
```powershell
streamlit run app/main.py
```
The application will automatically open in your default browser at:
`http://localhost:8501`

---

## 💾 Model Artifacts Notice

To adhere to GitHub's **100 MB hard limit**, the large model `random_forest.joblib` (106.3 MB) is excluded from Git via `.gitignore`. 

- **Pre-packaged in local repository:** `logistic_regression.joblib` (4.3 KB), `decision_tree.joblib` (985 KB), and `ThreatLens_LSTM_Model.keras` (325 KB).
- **For full Random Forest inference:** Ensure `random_forest.joblib` is placed inside the `models/` directory. If absent, ThreatLens gracefully falls back to the remaining three models without crashing.

---

## 🧪 Testing and Quality Assurance

Run the comprehensive Pytest suite:
```powershell
python -m pytest -v
```

Test coverage includes:
- **Preprocessing:** Empty CSV handling, column alias resolution, feature reordering, missing feature detection, non-numeric imputation.
- **Model Loader:** Model availability, file existence, parameter validation, Keras 3 deserialization patch.
- **Inference:** Prediction consistency on test batches across all models, output probability bounds.
- **Rules & Decision Engine:** Threshold condition checks, unanimous consensus, plurality with rules, tie-breaking and disagreement escalation.
- **Database & Reports:** SQLite scan lifecycle, metrics aggregation, PDF generation, CSV export formatting.

---

## ⚖️ Ethical Considerations, Fairness & Limitations

1. **Decision Support, Not Autonomous Blocking:** ThreatLens is an advisory SOC tool. Analysts must verify high-severity alerts before executing host isolation or traffic blocking.
2. **Dataset Class Imbalance:** In realistic network captures, benign events comprise >80% of samples. Rare attack categories (Heartbleed, SQL Injection) have smaller sample representation, which analysts should consider during triage.
3. **Privacy by Design:** ThreatLens operates exclusively on aggregated network flow metadata (packet counts, segment sizes, inter-arrival times) rather than inspecting private message contents or decrypted payload data.

---

## 📜 Git & GitHub Workflow for Beginners

When making new changes:

1. **Pull latest changes:**
   ```powershell
   git pull origin main
   ```
2. **Run tests before committing:**
   ```powershell
   python -m pytest -v
   ```
3. **Check modified files:**
   ```powershell
   git status
   ```
4. **Stage selected files (never stage large datasets or models over 100MB):**
   ```powershell
   git add app/ src/ tests/ README.md
   ```
5. **Commit with a descriptive message:**
   ```powershell
   git commit -m "feat: enhance SOC decision support UI and report generation"
   ```
6. **Push to GitHub:**
   ```powershell
   git push origin main
   ```

---

## 👥 Contributors & Academic Attribution
- **Author:** Ryan Norman
- **Project:** ThreatLens Decision Support System
- **Academic Foundation:** Tasks 1 through 10 (State Space Search, Feature Extraction, ML/DL Classification, Interpretability, Multi-Model Pipeline Integration, and Model Validation).