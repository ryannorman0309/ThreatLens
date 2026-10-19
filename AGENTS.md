# ThreatLens Agent Guide

## System Instructions & Architecture

This repository contains **ThreatLens**, an AI-powered cybersecurity log analysis and decision-support web application.

### Key Architecture Components
- **`app/main.py`**: Streamlit application with multi-page navigation (Dashboard, Log Triage, Benchmarks, Explainability, History, Architecture).
- **`src/config.py`**: Central configuration with the exact 20 feature names, 15 class names, empirical rule thresholds, and paths.
- **`src/preprocessing.py`**: Input validation, column alias resolution, feature reordering, missing value imputation.
- **`src/model_loader.py`**: Model loading and Keras 3.12 compatibility patch (`Dense.from_config` bypass for `quantization_config`).
- **`src/predict.py`**: Unified inference across Logistic Regression, Decision Tree, Random Forest, and LSTM (`(N, 1, 20)` 3D tensor).
- **`src/rules.py`**: Statistical outlier AI rule engine ($Q_3 + 1.5 \times IQR$) generating `R-OUTLIER` evidence strings.
- **`src/decision_engine.py`**: Task 9 consensus pipeline, tie-breaking, disagreement handling, and SOC recommendations.
- **`src/explain.py`**: Feature importance, error patterns, and individual event local reasoning.
- **`src/evaluation.py`**: Static Task 9/10 benchmarks and dynamic evaluation against ground truth.
- **`src/database.py`**: SQLite database (`data/threatlens.db`) tracking scan history.
- **`src/reports.py`**: ReportLab executive PDF generator and CSV export.

### Notebooks & Tasks (Tasks 2 to 10)
- **`notebooks/ThreatLens_Task2_Rule_Engine.ipynb`**: Task 2 forward-chaining expert system (rules R001-R008).
- **`notebooks/ThreatLens_Task3_State_Space_Search_Colab_Completed.ipynb`**: Task 3 state-space model & search algorithms (BFS, DFS, A*).
- **`notebooks/ThreatLens_Task4_Complete.ipynb`**: Task 4 data collection, cleaning, EDA & outlier detection.
- **`notebooks/ThreatLens_Task5_Feature_Engineering.ipynb`**: Task 5 feature extraction, mutual info & 20-feature selection.
- **`notebooks/CIL_TASK6.ipynb`**: Task 6 machine learning models (Logistic Regression, Decision Tree, Random Forest).
- **`notebooks/CIL_TASK7.ipynb`**: Task 7 LSTM deep learning sequence formatting, compilation & training.
- **`notebooks/CIL_TASK8.ipynb`**: Task 8 LSTM evaluation, internal activations & misclassification pattern analysis.
- **`notebooks/CIL_task9.ipynb`**: Task 9 multi-model consensus, empirical outlier rule fusion & SOC recommendations.

### Running Tests
```powershell
python -m pytest -v
```

### Running Application
```powershell
streamlit run app/main.py
```

### Git Safety Rules
- `models/random_forest.joblib` (111.4 MB) exceeds GitHub's 100MB limit and is ignored in `.gitignore`. Never force-add it.
- Large CSVs (`ThreatLens_X_train.csv`, `ThreatLens_Cleaned.csv`, `ThreatLens_X_test.csv`, `ThreatLens_Task9_Final_Report.csv`) are external to avoid repository bloat.
- `artifacts/sample_test_logs.csv` (500 rows) is committed for automated tests and demo usage.
