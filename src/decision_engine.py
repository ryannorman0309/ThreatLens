"""ThreatLens Task 9 Integrated Decision-Support Pipeline.

Combines Rule-Based AI Evidence, Traditional Machine Learning, and Deep Learning
into an explainable, consensus-driven cybersecurity triage verdict.
"""

import pandas as pd
import numpy as np
from collections import Counter
from typing import Dict, Any, List, Optional
from src.config import CLASS_NAMES, SEVERITY_LEVELS, THREAT_CATEGORIES, setup_logger

logger = setup_logger("threatlens.decision_engine")

def run_decision_pipeline(
    predictions_by_model: Dict[str, np.ndarray],
    confidences_by_model: Dict[str, np.ndarray],
    rule_triggered: np.ndarray,
    rule_evidence: List[str]
) -> pd.DataFrame:
    """Executes the Task 9 multi-model consensus and rule integration pipeline.
    
    Returns:
        DataFrame containing enriched decision records with agreement, status,
        explanations, and recommended actions.
    """
    model_names = list(predictions_by_model.keys())
    n_samples = len(rule_triggered)
    total_models = len(model_names)

    predicted_classes: List[Optional[int]] = []
    predicted_labels: List[str] = []
    severities: List[str] = []
    threat_cats: List[str] = []
    model_agreements: List[float] = []
    decision_statuses: List[str] = []
    explanations: List[str] = []
    recommended_actions: List[str] = []

    for i in range(n_samples):
        # Collect predictions from each model for row i
        row_votes: Dict[str, int] = {}
        votes_list = []
        for name in model_names:
            pred_val = int(predictions_by_model[name][i])
            row_votes[name] = pred_val
            votes_list.append(pred_val)

        vote_counts = Counter(votes_list)
        highest_count = max(vote_counts.values())

        # Do not arbitrarily select a class if the vote is tied
        winners = [
            label for label, count in vote_counts.items()
            if count == highest_count
        ]

        consensus = winners[0] if len(winners) == 1 else None
        agreement = highest_count / total_models
        model_agreements.append(round(agreement, 3))

        is_rule = bool(rule_triggered[i])
        ev_str = rule_evidence[i]

        if consensus is None:
            final_status = "Model disagreement - investigate"
            predicted_classes.append(None)
            predicted_labels.append("Uncertain (Disagreement)")
            severities.append("High")  # Unresolved anomaly escalated
            threat_cats.append("Ambiguous Disagreement")
            action = (
                "Review the original log and compare model outputs. "
                "Escalate for analyst review if suspicious."
            )
        else:
            predicted_classes.append(consensus)
            lbl = CLASS_NAMES.get(consensus, f"Unknown ({consensus})")
            predicted_labels.append(lbl)
            severities.append(SEVERITY_LEVELS.get(lbl, "Medium"))
            threat_cats.append(THREAT_CATEGORIES.get(lbl, "Unknown Threat"))

            if is_rule:
                final_status = "Rule alert - investigate"
                action = (
                    "Inspect the rule-triggering fields and verify the event "
                    "against source logs before taking action."
                )
            elif agreement < 0.75:
                final_status = "Low agreement - investigate"
                action = (
                    "Review the event and validate it against additional "
                    "security evidence."
                )
            else:
                final_status = "Model consensus - review predicted class"
                action = (
                    "Review the predicted class and supporting evidence. "
                    "Do not treat model consensus alone as proof of safety."
                )

        decision_statuses.append(final_status)
        recommended_actions.append(action)

        # Build Explanation String matching Task 9 Colab
        pred_dict_str = ", ".join(f"'{k}': np.int64({v})" for k, v in row_votes.items())
        agreement_pct = int(round(agreement * 100))
        full_explanation = (
            f"Predictions: {{{pred_dict_str}}}. "
            f"Agreement: {agreement_pct}%. "
            f"AI rule evidence: {ev_str}."
        )
        explanations.append(full_explanation)

    # Assemble comprehensive results DataFrame
    results_df = pd.DataFrame({
        "Predicted_Class": predicted_classes,
        "Predicted_Label": predicted_labels,
        "Threat_Category": threat_cats,
        "Severity": severities,
        "Model_Agreement": model_agreements,
        "Rule_Triggered": rule_triggered,
        "Rule_Evidence": rule_evidence,
        "Decision_Status": decision_statuses,
        "Explanation": explanations,
        "Recommended_Action": recommended_actions,
    })

    # Append individual model prediction columns
    for name in model_names:
        col_name = f"{name.replace(' ', '_')}_Prediction"
        results_df[col_name] = predictions_by_model[name]

    logger.info("Integrated decision pipeline evaluated %d records.", n_samples)
    return results_df
