"""Unit Tests for Rule Engine and Task 9 Decision Engine."""

import pytest
import pandas as pd
import numpy as np
from src.config import FEATURE_NAMES, RULE_THRESHOLDS
from src.rules import evaluate_rules, get_rule_definitions
from src.decision_engine import run_decision_pipeline

def test_rule_evaluation():
    # Construct normal record (below thresholds)
    low_data = {feat: [thresh - 1.0] for feat, thresh in RULE_THRESHOLDS.items()}
    df_low = pd.DataFrame(low_data)

    triggered, evidence, counts = evaluate_rules(df_low)
    assert not triggered[0]
    assert evidence[0] == "No configured outlier rule matched"
    assert counts[0] == 0

    # Construct anomalous record (above threshold for 2 features)
    high_data = low_data.copy()
    high_data["numeric__Avg Packet Size"] = [RULE_THRESHOLDS["numeric__Avg Packet Size"] + 5.0]
    high_data["numeric__Init Fwd Win Bytes"] = [RULE_THRESHOLDS["numeric__Init Fwd Win Bytes"] + 5.0]
    df_high = pd.DataFrame(high_data)

    triggered, evidence, counts = evaluate_rules(df_high)
    assert triggered[0]
    assert counts[0] == 2
    assert "numeric__Avg Packet Size" in evidence[0]
    assert "numeric__Init Fwd Win Bytes" in evidence[0]

def test_decision_engine_consensus_and_disagreement():
    # Case 1: Unanimous consensus, no rules -> "Model consensus - review predicted class"
    preds_case1 = {
        "Logistic Regression": np.array([0]),
        "Decision Tree": np.array([0]),
        "Random Forest": np.array([0]),
        "LSTM": np.array([0])
    }
    rules_case1 = np.array([False])
    evidence_case1 = ["No configured outlier rule matched"]
    res1 = run_decision_pipeline(preds_case1, {}, rules_case1, evidence_case1)
    assert res1.iloc[0]["Predicted_Class"] == 0
    assert res1.iloc[0]["Model_Agreement"] == 1.0
    assert res1.iloc[0]["Decision_Status"] == "Model consensus - review predicted class"

    # Case 2: Plurality with rules -> "Rule alert - investigate"
    preds_case2 = {
        "Logistic Regression": np.array([0]),
        "Decision Tree": np.array([4]),
        "Random Forest": np.array([4]),
        "LSTM": np.array([4])
    }
    rules_case2 = np.array([True])
    evidence_case2 = ["R-OUTLIER: numeric__Avg Packet Size=2.5 exceeds training threshold 1.126"]
    res2 = run_decision_pipeline(preds_case2, {}, rules_case2, evidence_case2)
    assert res2.iloc[0]["Predicted_Class"] == 4
    assert res2.iloc[0]["Model_Agreement"] == 0.75
    assert res2.iloc[0]["Decision_Status"] == "Rule alert - investigate"

    # Case 3: 2-way tie -> "Model disagreement - investigate"
    preds_case3 = {
        "Logistic Regression": np.array([0]),
        "Decision Tree": np.array([6]),
        "Random Forest": np.array([6]),
        "LSTM": np.array([0])
    }
    rules_case3 = np.array([False])
    evidence_case3 = ["No configured outlier rule matched"]
    res3 = run_decision_pipeline(preds_case3, {}, rules_case3, evidence_case3)
    assert pd.isna(res3.iloc[0]["Predicted_Class"])
    assert res3.iloc[0]["Model_Agreement"] == 0.5
    assert res3.iloc[0]["Decision_Status"] == "Model disagreement - investigate"
