"""ThreatLens UI Custom Styling and Components."""

CYBER_CSS = """
<style>
/* Font and Base Settings */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Outfit:wght@300;400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Outfit', sans-serif;
}

code, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Glassmorphism Cards */
.cyber-card {
    background: rgba(17, 24, 39, 0.75);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(0, 229, 255, 0.2);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
    transition: all 0.3s ease;
}

.cyber-card:hover {
    border-color: rgba(0, 229, 255, 0.5);
    box-shadow: 0 8px 32px 0 rgba(0, 229, 255, 0.15);
}

/* Metric KPI Cards */
.metric-box {
    background: linear-gradient(135deg, rgba(19, 27, 46, 0.9) 0%, rgba(11, 15, 25, 0.9) 100%);
    border-left: 4px solid #00E5FF;
    border-radius: 8px;
    padding: 16px 20px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
}

.metric-title {
    font-size: 0.85rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #94A3B8;
    margin-bottom: 4px;
}

.metric-value {
    font-size: 1.8rem;
    font-weight: 700;
    color: #F8FAFC;
    font-family: 'JetBrains Mono', monospace;
}

.metric-sub {
    font-size: 0.75rem;
    color: #00E5FF;
    margin-top: 4px;
}

/* Status Badges */
.badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}

.badge-critical {
    background: rgba(239, 68, 68, 0.2);
    color: #EF4444;
    border: 1px solid rgba(239, 68, 68, 0.4);
}

.badge-high {
    background: rgba(249, 115, 22, 0.2);
    color: #F97316;
    border: 1px solid rgba(249, 115, 22, 0.4);
}

.badge-medium {
    background: rgba(245, 158, 11, 0.2);
    color: #F59E0B;
    border: 1px solid rgba(245, 158, 11, 0.4);
}

.badge-low {
    background: rgba(16, 185, 129, 0.2);
    color: #10B981;
    border: 1px solid rgba(16, 185, 129, 0.4);
}

.badge-cyan {
    background: rgba(0, 229, 255, 0.15);
    color: #00E5FF;
    border: 1px solid rgba(0, 229, 255, 0.3);
}

/* ThreatLens Header Banner */
.brand-title {
    font-size: 2.2rem;
    font-weight: 800;
    background: linear-gradient(90deg, #00E5FF 0%, #3B82F6 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -0.5px;
    margin-bottom: 0px;
}

.brand-subtitle {
    font-size: 0.95rem;
    color: #94A3B8;
    margin-bottom: 20px;
}
</style>
"""

def render_metric_card(title: str, value: str, subtext: str = "", border_color: str = "#00E5FF") -> str:
    """Returns HTML for a sleek metric box."""
    return f"""
    <div class="metric-box" style="border-left-color: {border_color};">
        <div class="metric-title">{title}</div>
        <div class="metric-value">{value}</div>
        {f'<div class="metric-sub" style="color: {border_color};">{subtext}</div>' if subtext else ''}
    </div>
    """

def get_severity_badge(severity: str) -> str:
    """Returns styled HTML badge for threat severity."""
    cls = {
        "Critical": "badge-critical",
        "High": "badge-high",
        "Medium": "badge-medium",
        "Low": "badge-low",
    }.get(severity, "badge-cyan")
    return f'<span class="badge {cls}">{severity}</span>'

def get_status_badge(status: str) -> str:
    """Returns styled HTML badge for decision status."""
    if "consensus" in status.lower():
        return f'<span class="badge badge-low">{status}</span>'
    elif "rule alert" in status.lower():
        return f'<span class="badge badge-high">{status}</span>'
    else:
        return f'<span class="badge badge-critical">{status}</span>'
