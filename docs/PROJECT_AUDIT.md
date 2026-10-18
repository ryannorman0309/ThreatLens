# ThreatLens — Comprehensive Project Audit

## 1. Executive Summary

**ThreatLens** is an AI-powered cybersecurity log analysis and decision-support system designed to assist security analysts in detecting, classifying, and explaining network security events and cyber threats.

This audit assesses all existing project artifacts created during academic tasks in Google Colab (Tasks 1 through 10), identifies compatibility constraints, catalogs genuine model files, verifies data schemas and class mappings, and outlines the exact baseline for the production-ready Streamlit web application.

---

## 2. Workspace & Environment Discovery

- **Workspace Path:** `c:\Users\Ryan\ryan\ThreatLens\ThreatLens`
- **Git Repository:** `https://github.com/ryannorman0309/ThreatLens.git`
- **Current Branch:** `main` (clean baseline tracking `origin/main`)
- **Python Environment:** Python 3.10.0 (Windows 64-bit)
- **Key Installed Libraries:**
  - `streamlit` 1.55.0
  - `tensorflow` 2.21.0 & `keras` 3.12.1
  - `scikit-learn` 1.7.2
  - `pandas` 2.3.3 & `numpy` 2.2.6
  - `matplotlib` 3.10.8 & `plotly` 7.1.0
  - `joblib` 1.5.3
  - `reportlab` 5.0.1
  - `pytest` 9.1.1

---

## 3. Inventory of Existing Academic Artifacts

All artifacts from the user's local system and Downloads folder were discovered and audited:

| Artifact Name | Location | Size | Type / Purpose | Audit Findings |
|---|---|---|---|---|
| `decision_tree.joblib` | `models/` | 985 KB | Trained Scikit-Learn Model | Verified: `DecisionTreeClassifier`, fits 20 features, outputs 15 classes. |
| `logistic_regression.joblib` | `models/` | 4.3 KB | Trained Scikit-Learn Model | Verified: `LogisticRegression`, fits 20 features, outputs 15 classes. |
| `random_forest.joblib` | `models/` | 106.3 MB | Trained Scikit-Learn Model | Verified: `RandomForestClassifier`. Exceeds GitHub 100MB limit; preserved locally in `models/` and added to `.gitignore`. |
| `ThreatLens_LSTM_Model.keras` | `models/` | 325 KB | Keras Sequential Model | Verified: Input shape `(None, 1, 20)`, 64 LSTM units, Dense(32), Dense(15, softmax). Deserialization requires Keras 3.12 compatibility patch (`quantization_config` bypass). |
| `ThreatLens_Feature_Metadata.csv` | `artifacts/` | 3.5 KB | Schema Metadata | Catalog of all original 78 network flow features and data types. |
| `ThreatLens_Feature_Importance.csv` | `artifacts/` | 3.6 KB | Task 5/8 Feature Ranking | Mutual information and random forest importance for the selected top 20 features. |
| `ThreatLens_Model_Evaluation.csv` | `artifacts/` | 317 B | Traditional ML Metrics | Accuracy, Precision, Recall, F1 for LR, DT, RF. |
| `ThreatLens_LSTM_Evaluation.csv` | `artifacts/` | 122 B | DL Metrics | Accuracy (99.16%), Precision (99.13%), Recall (99.16%), F1 (99.09%). |
| `ThreatLens_Task9_Model_Comparison.csv` | `artifacts/` | 397 B | 4-Model Benchmark | Comparative evaluation across LR, DT, RF, and LSTM. |
| `ThreatLens_Error_Summary.csv` | `artifacts/` | 195 B | Error Breakdown | Sample counts, misclassification counts, and error rates. |
| `ThreatLens_Error_Pattern_Comparison.csv` | `artifacts/` | 124 B | Error Profiling | Total errors and unique misclassification types per model. |
| `ThreatLens_DecisionTree_Misclassifications.csv` | `artifacts/` | 359 B | Misclassification Details | Top error pairs (e.g. Class 0 misclassified as 14, 12, 4, etc.). |
| `ThreatLens_Logistic_Misclassifications.csv` | `artifacts/` | 638 B | Misclassification Details | Top error pairs for Logistic Regression. |
| `ThreatLens_RandomForest_Misclassifications.csv` | `artifacts/` | 276 B | Misclassification Details | Top error pairs for Random Forest. |
| `ThreatLens_Ontology.owl` | `artifacts/` | 5.9 KB | OWL/XML Ontology | Classes, properties, hierarchy for security events, threats, risk levels. |
| `ThreatLens_Task4_Complete.ipynb` | `notebooks/` | 29 KB | Jupyter Notebook | Cleaning, class distribution, 78 features, binary vs multi-class analysis. |
| `ThreatLens_Task3_State_Space_Search...` | `notebooks/` | 159 KB | Jupyter Notebook | State-space graph, A* search over pipeline inspection states. |
| `sample_test_logs.csv` | `artifacts/` | 185 KB | Sample Test Dataset | 500 validated test rows from `ThreatLens_X_test.csv` with ground-truth `Actual_Class`. |
| `ThreatLens_X_train.csv` / `X_test.csv` | External (Downloads) | 725 MB / 181 MB | Preprocessed Dataset | 20 selected scaled features for training/testing. Kept external due to size. |
| `ThreatLens_Task9_Final_Report.csv` | External (Downloads) | 534 MB | Task 9 Output | Full dataset Task 9 pipeline decisions and rule evidence. Kept external due to size. |

---

## 4. Technical Specifications & Verified Mappings

### 4.1 Feature Order (20 Selected Input Features)
The trained models and LSTM require strictly ordered numeric features:
1. `numeric__Avg Packet Size`
2. `numeric__Bwd Packet Length Mean`
3. `numeric__Avg Bwd Segment Size`
4. `numeric__Subflow Bwd Bytes`
5. `numeric__Bwd Packets Length Total`
6. `numeric__Packet Length Mean`
7. `numeric__Packet Length Std`
8. `numeric__Packet Length Variance`
9. `numeric__Packet Length Max`
10. `numeric__Bwd Packet Length Max`
11. `numeric__Subflow Fwd Bytes`
12. `numeric__Fwd Packets Length Total`
13. `numeric__Bwd Packet Length Std`
14. `numeric__Fwd Packet Length Max`
15. `numeric__Init Bwd Win Bytes`
16. `numeric__Fwd IAT Max`
17. `numeric__Init Fwd Win Bytes`
18. `numeric__Fwd IAT Total`
19. `numeric__Flow IAT Max`
20. `numeric__Fwd IAT Mean`

*(Note: Raw logs can use standard column names without the `numeric__` prefix; the preprocessor automatically maps aliases).*

### 4.2 Target Column & 15 Class Labels
The target column is `Label` (encoded as integers 0 through 14 via standard alphabetic `LabelEncoder`):

| Code | Class Label Name | Threat Category | Severity Level |
|---|---|---|---|
| **0** | `Benign` | Normal Traffic | Info / Low |
| **1** | `Bot` | Botnet Traffic | High |
| **2** | `DDoS` | Distributed Denial of Service | Critical |
| **3** | `DoS GoldenEye` | Denial of Service | High |
| **4** | `DoS Hulk` | Denial of Service | High |
| **5** | `DoS Slowhttptest` | Denial of Service | Medium |
| **6** | `DoS slowloris` | Denial of Service | High |
| **7** | `FTP-Patator` | Brute Force Authentication | High |
| **8** | `Heartbleed` | Memory Disclosure Vulnerability | Critical |
| **9** | `Infiltration` | Network Infiltration | Critical |
| **10** | `PortScan` | Reconnaissance Probe | Medium |
| **11** | `SSH-Patator` | Brute Force Authentication | High |
| **12** | `Web Attack Brute Force` | Web Application Attack | High |
| **13** | `Web Attack Sql Injection` | SQL Injection Attack | Critical |
| **14** | `Web Attack XSS` | Cross-Site Scripting | Medium |

### 4.3 LSTM Model Architecture & Compatibility
- **Input Dimension:** 3D Tensor of shape `(Batch_Size, 1, 20)`
- **Layers:**
  1. `InputLayer` (shape: `[None, 1, 20]`)
  2. `LSTM` (64 units, `tanh` activation, `sigmoid` recurrent activation)
  3. `Dropout` (rate: 0.3)
  4. `Dense` (32 units, `relu` activation)
  5. `Dropout` (rate: 0.2)
  6. `Dense` (15 units, `softmax` activation)
- **Keras 3.12 Compatibility Issue Identified:**
  The saved `.keras` file was serialized with layer keyword `quantization_config=None`, causing Keras 3.12 `Dense` deserialization to raise `TypeError: Unrecognized keyword arguments passed to Dense`.
- **Solution Verified:**
  A lightweight compatibility patch in `src/model_loader.py` strips `quantization_config` during deserialization, allowing the exact original trained weights and architecture to load seamlessly and achieve **100% exact match** against saved test predictions.

### 4.4 Rule Engine & Task 9 Decision Policy
- **Rule Detection Logic:**
  Empirical statistical outlier detection based on upper quartile boundaries ($Q_3 + 1.5 \times IQR$) established during training across all 20 features. Features exceeding threshold fire rule `R-OUTLIER: <Feature>=<Val> exceeds training threshold <Threshold>`.
- **Decision Engine Status Matrix:**
  1. **Consensus (`Model consensus - review predicted class`):**
     Model agreement $\ge 75\%$ and no rule alerts fired.
  2. **Rule Alert (`Rule alert - investigate`):**
     Model agreement has a plurality (or $\ge 75\%$) and one or more `R-OUTLIER` rules fired.
  3. **Disagreement (`Model disagreement - investigate`):**
     Model agreement $\le 50\%$ with a tie between predicted classes (e.g. 2 models predict class A, 2 predict class B), requiring manual analyst triage.

---

## 5. What Can Be Reused vs What Must Be Built

### Can Be Reused Directly:
1. `decision_tree.joblib`, `logistic_regression.joblib`, `random_forest.joblib`
2. `ThreatLens_LSTM_Model.keras` (with deserialization patch)
3. Task 4 preprocessing logic & feature metadata
4. Task 8 feature importance and confusion/misclassification data
5. Task 9 decision rules, threshold dictionary, and explanation templates
6. Task 10 evaluation benchmarks

### Must Be Built for the Web Application:
1. **Application Core (`src/`):**
   - `src/preprocessing.py`: CSV validation, schema normalization, missing value handling.
   - `src/model_loader.py`: Safe cached loading of ML and DL models.
   - `src/predict.py`: Vectorized inference across all loaded models.
   - `src/rules.py`: Independent rule engine with explainable evidence output.
   - `src/decision_engine.py`: Task 9 multi-model consensus and disagreement resolution.
   - `src/explain.py`: Feature contribution and decision explanation logic.
   - `src/evaluation.py`: Precomputed benchmarks + dynamic evaluation if ground-truth labels exist.
   - `src/database.py`: SQLite database for storing scan history and record counts.
   - `src/reports.py`: CSV export and PDF executive report generator via ReportLab.
2. **Streamlit UI (`app/`):**
   - Modern, professional cybersecurity UI with dark theme, ThreatLens branding, sidebar navigation, metric cards, interactive Plotly visualizations, file uploader, batch scan table, and export downloads.
3. **Automated Test Suite (`tests/`):**
   - Unit tests for validation, models, LSTM, rules, decision engine, database, and report generation.

---

## 6. Audit Conclusion & Approval to Proceed
All necessary model files and task outputs exist and have been validated. The project foundation can now be implemented without synthetic data or speculative models.
