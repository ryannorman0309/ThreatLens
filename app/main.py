"""ThreatLens — AI-Powered Cybersecurity Log Decision-Support Web Application.

Pairs Traditional Machine Learning, LSTM Deep Learning, and Rule-Based AI
to triage and explain cybersecurity events for security operations.
"""

import os
import sys
from pathlib import Path

# Add project root to Python module search path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

from src.config import (
    FEATURE_NAMES, CLASS_NAMES, SEVERITY_LEVELS, SEVERITY_COLORS,
    THREAT_CATEGORIES, RULE_THRESHOLDS, ARTIFACTS_DIR
)
from src.model_loader import get_all_models, get_model_status
from src.preprocessing import validate_and_prepare_features
from src.predict import predict_all_models
from src.rules import evaluate_rules, get_rule_definitions
from src.decision_engine import run_decision_pipeline
from src.explain import get_feature_importance_data, get_model_misclassifications, explain_single_record
from src.evaluation import get_precomputed_benchmarks, evaluate_predictions_against_ground_truth
from src.database import init_db, save_scan, get_recent_scans, get_summary_metrics, clear_history
from src.reports import generate_pdf_report, convert_results_to_csv_bytes
from app.styles import CYBER_CSS, render_metric_card, get_severity_badge, get_status_badge

# Page Configuration
st.set_page_config(
    page_title="ThreatLens | Cybersecurity Decision Support",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Cyber Styling
st.markdown(CYBER_CSS, unsafe_allow_html=True)

# Initialize Database
init_db()

# Session State Initialization
if "last_results" not in st.session_state:
    st.session_state.last_results = None
if "last_meta" not in st.session_state:
    st.session_state.last_meta = None
if "last_X" not in st.session_state:
    st.session_state.last_X = None
if "last_ground_truth" not in st.session_state:
    st.session_state.last_ground_truth = None

# Sidebar
with st.sidebar:
    st.markdown('<div class="brand-title">🛡️ THREATLENS</div>', unsafe_allow_html=True)
    st.markdown('<div class="brand-subtitle">Cybersecurity Log Decision Support</div>', unsafe_allow_html=True)
    st.divider()

    navigation = st.radio(
        "Navigation Menu",
        [
            "🛡️ Dashboard Overview",
            "🔍 Log Triage & Analysis",
            "📊 Model Benchmarks (Task 10)",
            "🧠 Explainability & AI Rules",
            "📜 Scan History & Reports",
            "ℹ️ Architecture & Ethical Scope"
        ],
        index=0
    )

    st.divider()
    st.markdown("### 🤖 Model Readiness")
    model_status = get_model_status()
    for m_key, info in model_status.items():
        if info["loaded"]:
            st.markdown(f"🟢 **{info['name']}** `{info['file_size_mb']} MB`")
        else:
            st.markdown(f"🔴 **{info['name']}** (Unavailable)")

    st.divider()
    db_metrics = get_summary_metrics()
    st.markdown(f"**Database Records:** {db_metrics['total_records_analyzed']:,}")
    st.markdown(f"**Scans Completed:** {db_metrics['total_scans']}")


# -----------------------------------------------------------------------------
# PAGE 1: DASHBOARD OVERVIEW
# -----------------------------------------------------------------------------
if navigation == "🛡️ Dashboard Overview":
    st.markdown('<div class="brand-title">SOC Decision Support Dashboard</div>', unsafe_allow_html=True)
    st.markdown("Real-time cybersecurity log intelligence integrating rule-based reasoning, ML, and deep learning.")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(render_metric_card("Total Logs Analyzed", f"{db_metrics['total_records_analyzed']:,}", "Across historical scans", "#00E5FF"), unsafe_allow_html=True)
    with col2:
        st.markdown(render_metric_card("Threats Flagged", f"{db_metrics['total_threats_detected']:,}", "High/Critical severity", "#EF4444"), unsafe_allow_html=True)
    with col3:
        st.markdown(render_metric_card("Rule Violations", f"{db_metrics['total_rule_alerts']:,}", "Statistical anomalies", "#F59E0B"), unsafe_allow_html=True)
    with col4:
        st.markdown(render_metric_card("Active Models", f"{sum(1 for m in model_status.values() if m['loaded'])} / 4", "LR, DT, RF, LSTM", "#10B981"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_left, col_right = st.columns([3, 2])
    with col_left:
        st.markdown("### 🌐 Detection Pipeline Architecture")
        st.info(
            "ThreatLens processes raw network security events through a four-stage pipeline: "
            "(1) 20-feature normalization, (2) isolated statistical rule evaluation, (3) parallel multi-model "
            "inference (Logistic Regression, Decision Tree, Random Forest, and LSTM), and (4) consensus decision-support "
            "with explainable evidence."
        )

        st.markdown("### 📑 Recent Analysis Runs")
        recent = get_recent_scans(10)
        if recent:
            recent_df = pd.DataFrame(recent)[["id", "timestamp", "filename", "total_records", "threat_count", "rule_alerts", "primary_threat", "status"]]
            st.dataframe(recent_df, use_container_width=True, hide_index=True)
        else:
            st.info("No scans recorded yet. Go to **Log Triage & Analysis** to analyze your first log file.")

    with col_right:
        st.markdown("### 🎯 System Classification Scope")
        scope_data = pd.DataFrame([
            {"Class": name, "Category": THREAT_CATEGORIES.get(name, "Unknown"), "Severity": SEVERITY_LEVELS.get(name, "Medium")}
            for name in CLASS_NAMES.values()
        ])
        fig_scope = px.pie(
            scope_data,
            names="Category",
            title="Monitored Threat Categories",
            hole=0.45,
            color_discrete_sequence=px.colors.qualitative.Dark24
        )
        fig_scope.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#F3F4F6"),
            margin=dict(t=40, b=10, l=10, r=10)
        )
        st.plotly_chart(fig_scope, use_container_width=True)


# -----------------------------------------------------------------------------
# PAGE 2: LOG TRIAGE & ANALYSIS
# -----------------------------------------------------------------------------
elif navigation == "🔍 Log Triage & Analysis":
    st.markdown('<div class="brand-title">Cybersecurity Log Triage & Detection</div>', unsafe_allow_html=True)
    st.markdown("Upload a network security log CSV or load the pre-validated sample dataset.")

    col_btn1, col_btn2 = st.columns([1, 4])
    with col_btn1:
        load_sample = st.button("⚡ Load Sample Test Logs (500 records)", use_container_width=True)

    uploaded_file = st.file_uploader("Upload Security Log CSV", type=["csv"])

    input_df = None
    file_label = ""

    if load_sample:
        sample_path = ARTIFACTS_DIR / "sample_test_logs.csv"
        if sample_path.exists():
            input_df = pd.read_csv(sample_path)
            file_label = "sample_test_logs.csv"
            st.success("Loaded 500 validated test records from project artifacts.")
        else:
            st.error("Sample dataset file not found in artifacts.")
    elif uploaded_file is not None:
        try:
            input_df = pd.read_csv(uploaded_file)
            file_label = uploaded_file.name
        except Exception as e:
            st.error(f"Failed to parse CSV file: {e}")

    if input_df is not None:
        st.markdown("### 📋 Input Validation & Feature Verification")
        X_prepared, y_ground_truth, val_summary = validate_and_prepare_features(input_df)

        if not val_summary["is_valid"]:
            st.error("Validation Failed:")
            for err in val_summary["errors"]:
                st.error(f"• {err}")
        else:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Rows Validated", f"{val_summary['original_rows']:,}")
            c2.metric("Required Features", f"{len(FEATURE_NAMES)} / {len(FEATURE_NAMES)}")
            c3.metric("Anomalous Cells Imputed", f"{val_summary['imputed_cells']}")
            c4.metric("Ground Truth Target", "Detected" if val_summary["has_ground_truth"] else "Not Present")

            if val_summary["warnings"]:
                for w in val_summary["warnings"]:
                    st.warning(f"⚠️ {w}")

            if st.button("🚀 Run Full Decision Pipeline", type="primary", use_container_width=True):
                with st.spinner("Executing rule evaluation, ML models, and LSTM inference..."):
                    rule_triggered, rule_evidence, anomaly_counts = evaluate_rules(X_prepared)
                    preds_by_model, confs_by_model = predict_all_models(X_prepared)
                    results_df = run_decision_pipeline(preds_by_model, confs_by_model, rule_triggered, rule_evidence)

                    # Compute Summary Breakdown
                    total_records = len(results_df)
                    threat_mask = results_df["Predicted_Label"] != "Benign"
                    threat_count = int(threat_mask.sum())
                    benign_count = total_records - threat_count
                    rule_alerts = int(results_df["Rule_Triggered"].sum())
                    disagreements = int((results_df["Decision_Status"] == "Model disagreement - investigate").sum())
                    consensus_rate = float((results_df["Model_Agreement"] >= 0.75).mean())

                    # Primary threat
                    threat_only = results_df[threat_mask]
                    primary_threat = threat_only["Predicted_Label"].value_counts().index[0] if not threat_only.empty else "None (All Benign)"

                    # Class breakdown dictionary
                    class_breakdown = results_df["Predicted_Label"].value_counts().to_dict()

                    # Save to database
                    scan_id = save_scan(
                        filename=file_label,
                        total_records=total_records,
                        benign_count=benign_count,
                        threat_count=threat_count,
                        rule_alerts=rule_alerts,
                        model_disagreements=disagreements,
                        consensus_rate=consensus_rate,
                        primary_threat=primary_threat,
                        class_breakdown=class_breakdown
                    )

                    # Store in session state
                    st.session_state.last_results = results_df
                    st.session_state.last_X = X_prepared
                    st.session_state.last_ground_truth = y_ground_truth
                    st.session_state.last_meta = {
                        "scan_id": scan_id,
                        "filename": file_label,
                        "total_records": total_records,
                        "benign_count": benign_count,
                        "threat_count": threat_count,
                        "rule_alerts": rule_alerts,
                        "model_disagreements": disagreements,
                        "consensus_rate": consensus_rate,
                        "primary_threat": primary_threat,
                    }

    # Display Results if Available
    if st.session_state.last_results is not None:
        results_df = st.session_state.last_results
        meta = st.session_state.last_meta
        X_data = st.session_state.last_X

        st.divider()
        st.markdown(f"### 🎯 Decision Pipeline Results (Scan #{meta['scan_id']})")

        m1, m2, m3, m4 = st.columns(4)
        m1.markdown(render_metric_card("Processed Events", f"{meta['total_records']:,}", meta["filename"], "#00E5FF"), unsafe_allow_html=True)
        m2.markdown(render_metric_card("Threats Identified", f"{meta['threat_count']:,}", f"{(meta['threat_count']/meta['total_records']*100):.1f}% of total", "#EF4444"), unsafe_allow_html=True)
        m3.markdown(render_metric_card("Rule Alerts", f"{meta['rule_alerts']:,}", "Outlier flags", "#F59E0B"), unsafe_allow_html=True)
        m4.markdown(render_metric_card("Consensus Rate", f"{(meta['consensus_rate']*100):.1f}%", f"{meta['model_disagreements']} ties", "#10B981"), unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Filters for Table
        filter_col1, filter_col2, filter_col3 = st.columns(3)
        with filter_col1:
            severity_filter = st.multiselect("Filter by Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
        with filter_col2:
            status_filter = st.multiselect("Filter by Decision Status", results_df["Decision_Status"].unique().tolist(), default=results_df["Decision_Status"].unique().tolist())
        with filter_col3:
            rules_only = st.checkbox("Show only records with AI Rule alerts", value=False)

        filtered_df = results_df[
            results_df["Severity"].isin(severity_filter) &
            results_df["Decision_Status"].isin(status_filter)
        ]
        if rules_only:
            filtered_df = filtered_df[filtered_df["Rule_Triggered"] == True]

        st.markdown(f"**Displaying {len(filtered_df):,} matching events:**")
        display_cols = ["Predicted_Label", "Severity", "Threat_Category", "Model_Agreement", "Decision_Status", "Rule_Triggered", "Recommended_Action"]
        st.dataframe(filtered_df[display_cols], use_container_width=True, height=350)

        # Drilldown Section
        st.markdown("### 🔬 Individual Event Drilldown & Local Reasoning")
        selected_idx = st.number_input("Enter Record Row Index to Inspect:", min_value=0, max_value=len(results_df)-1, value=0)

        record_features = X_data.iloc[selected_idx]
        record_decision = results_df.iloc[selected_idx]
        explanation_data = explain_single_record(record_features, record_decision)

        col_d1, col_d2 = st.columns([1, 2])
        with col_d1:
            st.markdown(f"**Predicted Threat:** `{explanation_data['predicted_label']}`")
            st.markdown(f"**Severity:** {get_severity_badge(explanation_data['severity'])}", unsafe_allow_html=True)
            st.markdown(f"**Category:** `{explanation_data['threat_category']}`")
            st.markdown(f"**Decision Status:** {get_status_badge(explanation_data['decision_status'])}", unsafe_allow_html=True)
            st.markdown(f"**Model Agreement:** `{int(explanation_data['model_agreement']*100)}%`")
            st.markdown(f"**Rule Triggered:** `{'Yes' if explanation_data['rule_triggered'] else 'No'}`")
            st.info(f"**SOC Action:** {explanation_data['recommended_action']}")

        with col_d2:
            st.markdown("**Top Feature Values vs Outlier Thresholds:**")
            dev_df = pd.DataFrame(explanation_data["feature_deviations"]).head(8)
            fig_dev = go.Figure()
            fig_dev.add_trace(go.Bar(
                x=dev_df["feature"],
                y=dev_df["value"],
                name="Event Value",
                marker_color="#00E5FF"
            ))
            fig_dev.add_trace(go.Scatter(
                x=dev_df["feature"],
                y=dev_df["threshold"],
                name="Training Anomaly Threshold",
                mode="lines+markers",
                line=dict(color="#EF4444", width=2, dash="dash")
            ))
            fig_dev.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#F3F4F6"),
                height=300,
                margin=dict(t=20, b=40, l=20, r=20)
            )
            st.plotly_chart(fig_dev, use_container_width=True)

        st.markdown(f"**Detailed Reasoning Explanation:** `{record_decision['Explanation']}`")

        # Download Buttons
        st.divider()
        st.markdown("### 📥 Export Scan Reports")
        dcol1, dcol2 = st.columns(2)

        with dcol1:
            csv_bytes = convert_results_to_csv_bytes(results_df)
            st.download_button(
                label="📄 Download Enriched Decision CSV",
                data=csv_bytes,
                file_name=f"ThreatLens_Decisions_Scan_{meta['scan_id']}.csv",
                mime="text/csv",
                use_container_width=True
            )

        with dcol2:
            threat_summary_df = results_df["Predicted_Label"].value_counts().reset_index()
            threat_summary_df.columns = ["Class", "Count"]
            threat_summary_df["Percentage"] = (threat_summary_df["Count"] / len(results_df) * 100).round(2)
            threat_summary_df["Severity"] = threat_summary_df["Class"].map(SEVERITY_LEVELS)
            threat_summary_df["Category"] = threat_summary_df["Class"].map(THREAT_CATEGORIES)

            benchmarks = get_precomputed_benchmarks()
            pdf_bytes = generate_pdf_report(meta, threat_summary_df, benchmarks)
            st.download_button(
                label="📑 Download Executive Security PDF Report",
                data=pdf_bytes,
                file_name=f"ThreatLens_Audit_Report_Scan_{meta['scan_id']}.pdf",
                mime="application/pdf",
                use_container_width=True
            )


# -----------------------------------------------------------------------------
# PAGE 3: MODEL BENCHMARKS (TASK 10)
# -----------------------------------------------------------------------------
elif navigation == "📊 Model Benchmarks (Task 10)":
    st.markdown('<div class="brand-title">Model Evaluation & Benchmark Validation</div>', unsafe_allow_html=True)
    st.markdown("Validated metrics and comparative performance across all four models on the held-out test dataset.")

    benchmarks_df = get_precomputed_benchmarks()
    if not benchmarks_df.empty:
        st.markdown("### 🏆 Comprehensive Model Comparison")
        st.dataframe(benchmarks_df, use_container_width=True, hide_index=True)

        fig_bench = go.Figure()
        f1_col = "F1 Score" if "F1 Score" in benchmarks_df.columns else "F1-Score"
        for metric, col_color in [("Accuracy", "#00E5FF"), ("Precision", "#3B82F6"), ("Recall", "#10B981"), (f1_col, "#F59E0B")]:
            fig_bench.add_trace(go.Bar(
                name=metric,
                x=benchmarks_df["Model"],
                y=benchmarks_df[metric],
                marker_color=col_color
            ))
        fig_bench.update_layout(
            barmode="group",
            yaxis=dict(range=[0.65, 1.05]),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#F3F4F6"),
            title="Model Evaluation Metrics Comparison"
        )
        st.plotly_chart(fig_bench, use_container_width=True)

    # Dynamic Evaluation Mode if Ground Truth was uploaded in the current session
    if st.session_state.last_results is not None and st.session_state.last_ground_truth is not None:
        st.divider()
        st.markdown("### 🧪 Live Evaluation Against Uploaded Ground Truth")
        y_true = st.session_state.last_ground_truth
        results_df = st.session_state.last_results

        eval_models = ["Logistic_Regression_Prediction", "Decision_Tree_Prediction", "Random_Forest_Prediction", "LSTM_Prediction", "Predicted_Class"]
        dyn_rows = []
        for em in eval_models:
            if em in results_df.columns:
                m_label = em.replace("_Prediction", "").replace("_", " ")
                eval_metrics = evaluate_predictions_against_ground_truth(y_true, results_df[em], m_label)
                if "error" not in eval_metrics:
                    dyn_rows.append({
                        "Model": m_label,
                        "Accuracy": eval_metrics["accuracy"],
                        "Precision (Macro)": eval_metrics["precision_macro"],
                        "Recall (Macro)": eval_metrics["recall_macro"],
                        "F1 (Macro)": eval_metrics["f1_macro"],
                        "F1 (Weighted)": eval_metrics["f1_weighted"],
                    })

        if dyn_rows:
            dyn_df = pd.DataFrame(dyn_rows)
            st.dataframe(dyn_df, use_container_width=True, hide_index=True)


# -----------------------------------------------------------------------------
# PAGE 4: EXPLAINABILITY & AI RULES
# -----------------------------------------------------------------------------
elif navigation == "🧠 Explainability & AI Rules":
    st.markdown('<div class="brand-title">Explainability & AI Rule Engine</div>', unsafe_allow_html=True)
    st.markdown("Global feature importance rankings from Tasks 5 & 8 alongside rule-based AI threshold specifications.")

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("### 🌟 Feature Importance Ranking")
        feat_df = get_feature_importance_data()
        if not feat_df.empty:
            fig_feat = px.bar(
                feat_df.head(15),
                x="Mutual_Information",
                y="Clean_Feature",
                orientation="h",
                title="Top 15 Features by Mutual Information Score",
                color="Mutual_Information",
                color_continuous_scale="Viridis"
            )
            fig_feat.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#F3F4F6"),
                yaxis=dict(autorange="reversed")
            )
            st.plotly_chart(fig_feat, use_container_width=True)

    with col2:
        st.markdown("### ⚖️ AI Outlier Rules & Knowledge Representation")
        rule_defs = get_rule_definitions()
        rules_df = pd.DataFrame(rule_defs)[["feature", "threshold", "logic", "description"]]
        st.dataframe(rules_df, use_container_width=True, height=450, hide_index=True)

    st.divider()
    st.markdown("### 📉 Misclassification Patterns & Error Distributions")
    misclass = get_model_misclassifications()
    tab1, tab2, tab3 = st.tabs(["Random Forest Errors", "Decision Tree Errors", "Logistic Regression Errors"])

    with tab1:
        if "Random Forest" in misclass:
            st.dataframe(misclass["Random Forest"], use_container_width=True, hide_index=True)
    with tab2:
        if "Decision Tree" in misclass:
            st.dataframe(misclass["Decision Tree"], use_container_width=True, hide_index=True)
    with tab3:
        if "Logistic Regression" in misclass:
            st.dataframe(misclass["Logistic Regression"], use_container_width=True, hide_index=True)


# -----------------------------------------------------------------------------
# PAGE 5: SCAN HISTORY & REPORTS
# -----------------------------------------------------------------------------
elif navigation == "📜 Scan History & Reports":
    st.markdown('<div class="brand-title">Historical Scans & Persistent Audit Trail</div>', unsafe_allow_html=True)
    st.markdown("Persistent SQLite audit database tracking all executed triage jobs.")

    scans = get_recent_scans(50)
    if scans:
        hist_df = pd.DataFrame(scans)
        st.dataframe(
            hist_df[["id", "timestamp", "filename", "total_records", "benign_count", "threat_count", "rule_alerts", "model_disagreements", "consensus_rate", "primary_threat", "status"]],
            use_container_width=True,
            hide_index=True
        )

        col_clr, _ = st.columns([1, 4])
        with col_clr:
            if st.button("🗑️ Clear Audit History", type="secondary"):
                clear_history()
                st.success("Audit database history cleared.")
                st.rerun()
    else:
        st.info("No scans recorded in the database yet.")


# -----------------------------------------------------------------------------
# PAGE 6: ARCHITECTURE & ETHICAL SCOPE
# -----------------------------------------------------------------------------
elif navigation == "ℹ️ Architecture & Ethical Scope":
    st.markdown('<div class="brand-title">System Architecture & Ethical Disclosures</div>', unsafe_allow_html=True)

    st.markdown("""
    ### 🛡️ ThreatLens Pipeline Architecture
    ThreatLens is built on the academic findings of Tasks 1 through 10, combining empirical cybersecurity heuristics with advanced machine learning.
    
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

    ### ⚖️ Ethical, Fairness, and Bias Considerations (Task 10)
    1. **Class Imbalance Realities:**
       The training dataset represents realistic network traffic where >80% of events are benign. While achieving >99% overall accuracy, rare attacks such as Heartbleed and Infiltration have limited sample representation.
    2. **Human-in-the-Loop Requirement:**
       ThreatLens is intentionally architected as a **decision-support tool**, not an autonomous threat blocking mechanism. Security analysts must evaluate rule alerts and model disagreements before taking disruptive containment actions.
    3. **Privacy by Design:**
       ThreatLens operates on numerical traffic flow statistics (packet lengths, inter-arrival times, window sizes) rather than private user payload data or plaintext communications.
    """)
