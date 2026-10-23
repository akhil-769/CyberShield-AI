"""Streamlit user interface for CyberShield AI security-log triage."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from html import escape

import pandas as pd
import plotly.express as px
import streamlit as st

from cybershield.config import DEFAULT_DETECTION_CONFIG
from cybershield.detection import analyze_events, detection_summary
from cybershield.ingest import parse_log_text
from cybershield.reporting import export_records_csv, export_records_json, export_summary_json

ROOT = Path(__file__).resolve().parent
SAMPLE_FILE = ROOT / "data" / "sample_security.jsonl"
SEVERITY_ORDER = ["Critical", "High", "Guarded", "Low"]
SEVERITY_COLORS = {"Critical": "#b9384b", "High": "#df6a59", "Guarded": "#c6892f", "Low": "#0e9384"}

st.set_page_config(page_title="CyberShield AI | Security Triage", page_icon="🛡️", layout="wide")

try:
    st.markdown(f"<style>{(ROOT / 'assets' / 'theme.css').read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)
except OSError:
    # The fallback is intentionally harmless; packaged deployments should include assets/theme.css.
    pass


def _initialise_state() -> None:
    """Load the included synthetic dataset once per browser session."""

    if "raw_events" not in st.session_state:
        sample_text = SAMPLE_FILE.read_text(encoding="utf-8")
        result = parse_log_text(sample_text, filename=SAMPLE_FILE.name)
        st.session_state.raw_events = result.events
        st.session_state.ingestion_issues = result.issues
        st.session_state.source_label = "Included synthetic dataset"
        st.session_state.source_format = result.source_format


def _header(eyebrow: str, title: str, subtitle: str) -> None:
    st.markdown(
        f'<div class="cs-header"><div class="cs-eyebrow">{eyebrow}</div>'
        f'<h1>{title}</h1><p>{subtitle}</p></div>',
        unsafe_allow_html=True,
    )


def _section(title: str, subtitle: str | None = None) -> None:
    st.markdown(f'<div class="cs-section">{title}</div>', unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="cs-subtitle">{subtitle}</div>', unsafe_allow_html=True)


def _records_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    """Prepare a display-only table without modifying underlying report records."""

    if not records:
        return pd.DataFrame(columns=["timestamp", "severity", "risk_score", "source_ip", "username", "event_type", "result"])
    frame = pd.DataFrame(records).copy()
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame["evidence_summary"] = frame["evidence"].apply(lambda values: " · ".join(values) if isinstance(values, list) else str(values))
    return frame


def _source_load_controls() -> None:
    """Upload a user-selected log file or restore the bundled synthetic data."""

    with st.sidebar:
        st.markdown("### Data source")
        st.caption("Local-only analysis. Uploaded logs remain in this browser session.")
        uploaded = st.file_uploader("Choose log file", type=["json", "jsonl", "ndjson", "csv", "log", "txt"])
        if st.button("Load selected file", use_container_width=True, disabled=uploaded is None):
            try:
                text = uploaded.getvalue().decode("utf-8-sig")
                result = parse_log_text(text, filename=uploaded.name)
                if not result.events:
                    st.error("No valid events were parsed. Check the file format and parsing notes.")
                else:
                    st.session_state.raw_events = result.events
                    st.session_state.ingestion_issues = result.issues
                    st.session_state.source_label = uploaded.name
                    st.session_state.source_format = result.source_format
                    st.success(f"Loaded {len(result.events):,} events from {escape(str(uploaded.name))}.")
            except (UnicodeDecodeError, ValueError, TypeError) as exc:
                st.error(f"Could not load the file: {exc}")
        if st.button("Restore sample data", use_container_width=True):
            sample_text = SAMPLE_FILE.read_text(encoding="utf-8")
            result = parse_log_text(sample_text, filename=SAMPLE_FILE.name)
            st.session_state.raw_events = result.events
            st.session_state.ingestion_issues = result.issues
            st.session_state.source_label = "Included synthetic dataset"
            st.session_state.source_format = result.source_format
            st.success("Included sample data restored.")
        st.markdown("---")
        use_ml = st.toggle("Local anomaly model", value=True, help="Uses Isolation Forest on this loaded batch when at least 20 events are present. Outliers are not proof of attack.")
        st.session_state.use_anomaly_model = use_ml
        st.caption("No logs are uploaded to a third-party service by this app.")


def _current_analysis() -> tuple[list[dict[str, Any]], dict[str, Any], pd.DataFrame]:
    raw_events = st.session_state.get("raw_events", [])
    use_ml = bool(st.session_state.get("use_anomaly_model", True))
    records = analyze_events(raw_events, config=DEFAULT_DETECTION_CONFIG, use_anomaly_model=use_ml)
    summary = detection_summary(records)
    frame = _records_frame(records)
    return records, summary, frame


def _overview(records: list[dict[str, Any]], summary: dict[str, Any], frame: pd.DataFrame) -> None:
    _header("DEFENSIVE SECURITY WORKBENCH", "CyberShield AI", "A calmer way to investigate noisy logs. Find patterns, see the evidence, and decide what deserves a closer look.")
    safe_source = escape(str(st.session_state.source_label))
    safe_format = escape(str(st.session_state.source_format).upper())
    source_chips = (
        f'<span class="cs-chip cs-chip-teal">SOURCE · {safe_source}</span> '
        f'<span class="cs-chip cs-chip-violet">FORMAT · {safe_format}</span>'
    )
    if "synthetic" in str(st.session_state.source_label).lower():
        source_chips += ' <span class="cs-chip cs-chip-amber">SYNTHETIC SAMPLE LABELLED</span>'
    st.markdown(source_chips, unsafe_allow_html=True)
    st.write("")

    columns = st.columns(5)
    columns[0].metric("Events reviewed", f"{summary['total_events']:,}")
    columns[1].metric("Critical findings", f"{summary['critical']:,}")
    columns[2].metric("High findings", f"{summary['high']:,}")
    columns[3].metric("Failed logins", f"{summary['failed_logins']:,}")
    columns[4].metric("Unique sources", f"{summary['unique_sources']:,}")

    if not records:
        st.info("No events are loaded yet. Upload JSON/JSONL, CSV, or a supported SSH authentication log.")
        return

    _section("Security pulse", "A compact view of activity in the loaded dataset, not a live network monitor.")
    left, right = st.columns([1.45, 1])
    with left:
        timed = frame.dropna(subset=["timestamp"]).copy()
        timed["time_bucket"] = timed["timestamp"].dt.floor("30min")
        trend = timed.groupby(["time_bucket", "severity"], as_index=False).size()
        trend = trend.rename(columns={"size": "Events"})
        fig = px.area(trend, x="time_bucket", y="Events", color="severity", category_orders={"severity": SEVERITY_ORDER},
                      color_discrete_map=SEVERITY_COLORS, template="plotly_white", title="Event volume by triage level")
        fig.update_layout(margin=dict(l=12, r=12, t=48, b=10), legend_title_text="Triage level", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        fig.update_xaxes(title=None, showgrid=False)
        fig.update_yaxes(title="Events", gridcolor="#e7eeea", rangemode="tozero")
        st.plotly_chart(fig, use_container_width=True)
    with right:
        severity = pd.DataFrame([{"Triage level": level, "Events": int((frame["severity"] == level).sum())} for level in SEVERITY_ORDER])
        fig = px.bar(severity, x="Events", y="Triage level", color="Triage level", color_discrete_map=SEVERITY_COLORS,
                     category_orders={"Triage level": SEVERITY_ORDER}, template="plotly_white", title="Current risk distribution", orientation="h")
        fig.update_layout(showlegend=False, margin=dict(l=12, r=12, t=48, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        fig.update_xaxes(title=None, showgrid=True, gridcolor="#e7eeea")
        fig.update_yaxes(title=None, showgrid=False)
        st.plotly_chart(fig, use_container_width=True)

    _section("Start with these findings", "Higher-scored records first. A score prioritises review; it does not establish malicious intent.")
    high_risk = [item for item in records if item["severity"] in {"Critical", "High"}][:8]
    if high_risk:
        show = pd.DataFrame([{
            "Time (UTC)": item["timestamp"], "Triage": item["severity"], "Score": item["risk_score"],
            "Source": item["source_ip"] or "Unknown", "Account": item["username"], "Event": item["event_type"],
            "Why it surfaced": " · ".join(item["evidence"][:2]),
        } for item in high_risk])
        st.dataframe(show, use_container_width=True, hide_index=True)
        with st.expander("Review evidence and recommendations"):
            for item in high_risk[:5]:
                st.markdown(f"**{escape(str(item['severity']))} · {int(item['risk_score'])}/100 · {escape(str(item['username']))} · {escape(str(item['source_ip'] or 'Unknown source'))}**")
                st.markdown("**Evidence**")
                for evidence in item["evidence"]:
                    st.markdown(f"- {evidence}")
                st.markdown("**Suggested defensive checks**")
                for action in item["recommendations"]:
                    st.markdown(f"- {action}")
                st.markdown("---")
    else:
        st.success("No High or Critical records were scored in this batch. This is not a guarantee that the environment is safe.")

    issues = st.session_state.get("ingestion_issues", [])
    if issues:
        with st.expander(f"Parsing notes ({len(issues)})"):
            for issue in issues[:100]:
                line_text = f"Line {issue.line}: " if issue.line is not None else "Source: "
                st.write(f"{line_text}{issue.message}")
            if len(issues) > 100:
                st.caption("Only the first 100 parsing notes are shown in the UI.")


def _event_explorer(records: list[dict[str, Any]], frame: pd.DataFrame) -> None:
    _header("INVESTIGATE", "Event explorer", "Filter normalized events and trace every score back to readable evidence.")
    if frame.empty:
        st.info("No parsed events are available.")
        return
    a, b, c, d = st.columns([1, 1, 1, 1.25])
    severity_filter = a.multiselect("Triage level", SEVERITY_ORDER, default=["Critical", "High", "Guarded", "Low"])
    result_filter = b.multiselect("Outcome", ["failure", "success", "unknown"], default=["failure", "success", "unknown"])
    type_options = sorted(str(x) for x in frame["event_type"].dropna().unique())
    type_filter = c.multiselect("Event type", type_options, default=type_options)
    needle = d.text_input("Search fields", placeholder="username, IP, message, host…")

    filtered = frame[frame["severity"].isin(severity_filter) & frame["result"].isin(result_filter) & frame["event_type"].isin(type_filter)]
    if needle.strip():
        pattern = needle.strip().lower()
        mask = filtered[["username", "source_ip", "message", "host", "service", "event_type"]].fillna("").astype(str).apply(
            lambda col: col.str.lower().str.contains(pattern, regex=False)
        ).any(axis=1)
        filtered = filtered[mask]

    st.caption(f"Showing {len(filtered):,} of {len(frame):,} events")
    display_columns = ["timestamp", "severity", "risk_score", "source_ip", "username", "event_type", "result", "service", "host"]
    st.dataframe(filtered[display_columns].rename(columns={"timestamp": "Timestamp (UTC)", "severity": "Triage", "risk_score": "Risk", "source_ip": "Source IP", "event_type": "Event type", "result": "Outcome"}), use_container_width=True, hide_index=True)

    _section("Event detail", "Choose a record to inspect evidence and recommended follow-up.")
    options = {f"{item['severity']} · {item['risk_score']:>3}/100 · {item['timestamp']} · {item['username']} · {item['source_ip'] or 'Unknown'}": item for item in filtered.to_dict("records")}
    if options:
        selected_label = st.selectbox("Selected event", list(options.keys()))
        chosen = options[selected_label]
        st.markdown("**Message**")
        st.code(str(chosen.get("message") or "(No message supplied)"), language=None)
        x, y = st.columns(2)
        with x:
            st.markdown("**Explainable signals**")
            for evidence in chosen.get("evidence", []):
                st.markdown(f"- {evidence}")
        with y:
            st.markdown("**Defensive recommendations**")
            for action in chosen.get("recommendations", []):
                st.markdown(f"- {action}")
    else:
        st.info("No event matches the current filters.")


def _detection_lab(records: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    _header("EXPLAIN THE SIGNAL", "Detection lab", "See which rules fired, how scoring is composed, and where a local anomaly model helps or misleads.")
    signal_counts = summary.get("signal_counts", {})
    if signal_counts:
        signal_frame = pd.DataFrame([{"Signal": key.replace("_", " ").title(), "Events": value} for key, value in signal_counts.items()]).sort_values("Events", ascending=True)
        fig = px.bar(signal_frame, x="Events", y="Signal", orientation="h", color="Events", color_continuous_scale=["#cdeee5", "#0e9384", "#7768d8"], template="plotly_white", title="Detection signal frequency")
        fig.update_layout(coloraxis_showscale=False, margin=dict(l=10, r=10, t=48, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        fig.update_xaxes(title=None, gridcolor="#e7eeea")
        fig.update_yaxes(title=None)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No detection signals fired in the loaded batch.")

    left, right = st.columns(2)
    with left:
        st.markdown('<div class="cs-panel"><h3>Rules in this build</h3><span class="cs-chip cs-chip-teal">Explainable</span><p>Failed-login bursts, username spraying, a success after repeated failures, administrative account activity, privilege-related events, sensitive paths, suspicious command patterns, and configured unusual-hours activity.</p><p>Rule points are added and capped at 100. Every finding includes an evidence list and bounded next-step suggestions.</p></div>', unsafe_allow_html=True)
    with right:
        outliers = sum(1 for record in records if record.get("is_dataset_outlier"))
        st.markdown(f'<div class="cs-panel"><h3>Local anomaly model</h3><span class="cs-chip cs-chip-violet">Isolation Forest</span><p><b>{outliers:,}</b> records are marked as dataset-relative outliers in this view.</p><p>The model is fitted to the current batch, requires at least 20 records, and has no labelled training set. An outlier is a prompt to inspect context, not a maliciousness verdict.</p></div>', unsafe_allow_html=True)

    _section("Scoring reference", "These weights are transparent defaults for demonstration. Tune and validate them against your organisation's data before operational use.")
    score_rows = [
        {"Indicator": "Failed login", "Default points": "+10", "Interpretation": "A failed authentication was logged."},
        {"Indicator": "Repeated failures from one source", "Default points": "+20 to +30", "Interpretation": "At least 5 login failures in a 15-minute window."},
        {"Indicator": "Username spraying", "Default points": "+15", "Interpretation": "Multiple distinct usernames tried from one source."},
        {"Indicator": "Successful login after failure burst", "Default points": "+18", "Interpretation": "Validate whether the success belongs to the account owner."},
        {"Indicator": "Privilege-related event", "Default points": "+28", "Interpretation": "Review command, change ticket, and least-privilege policy."},
        {"Indicator": "Dataset-relative outlier", "Default points": "+8", "Interpretation": "Local unsupervised anomaly flag; context is required."},
    ]
    st.dataframe(pd.DataFrame(score_rows), hide_index=True, use_container_width=True)
    st.caption("Severity bands: Low 0–24 · Guarded 25–49 · High 50–74 · Critical 75–100. Scores can saturate at 100.")


def _exports(records: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    _header("TAKE THE EVIDENCE WITH YOU", "Reports & exports", "Download a portable copy for a lab report or further offline analysis.")
    st.markdown('<div class="cs-callout">Exports contain normalized log messages, usernames, IPs, evidence, and recommended actions. Review them for sensitive data before sharing.</div>', unsafe_allow_html=True)
    st.write("")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button("Download events · CSV", data=export_records_csv(records), file_name="cybershield_events.csv", mime="text/csv", use_container_width=True)
        st.caption("Spreadsheet-friendly event-level findings.")
    with c2:
        st.download_button("Download events · JSON", data=export_records_json(records), file_name="cybershield_events.json", mime="application/json", use_container_width=True)
        st.caption("Structured detail for scripts and follow-on analysis.")
    with c3:
        st.download_button("Download summary · JSON", data=export_summary_json(summary), file_name="cybershield_summary.json", mime="application/json", use_container_width=True)
        st.caption("Aggregate counts for dashboard reporting.")
    st.write("")
    st.metric("Records included in export", f"{len(records):,}")
    st.caption("CyberShield AI does not automatically send results to external services or store uploaded files on disk.")


def _about() -> None:
    _header("PROJECT NOTES", "About & safety", "Designed as a defensive learning and analyst-triage project, not an autonomous incident responder.")
    left, right = st.columns(2)
    with left:
        st.markdown('<div class="cs-panel"><h3>What it does</h3><p>Parses JSON, JSON Lines, CSV, and common OpenSSH authentication logs. Normalizes records, detects repeated authentication failures and selected suspicious activity, scores risk with readable evidence, and suggests defensive verification steps.</p><p>Exports event-level findings and aggregate summaries as CSV or JSON. The application analyses logs locally inside the running Python process.</p></div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div class="cs-panel"><h3>What it does not do</h3><p>It does not block traffic, disable accounts, query live threat-intelligence services, or contact any external AI provider. The local recommendation engine uses deterministic templates; Isolation Forest is an optional unsupervised outlier aid.</p><p>It does not prove compromise or certify that quiet records are safe. False positives and false negatives are expected.</p></div>', unsafe_allow_html=True)
    _section("Safe demonstration practice")
    for line in [
        "Use only the bundled synthetic dataset or logs you are authorised to analyse.",
        "The included public IPs are reserved documentation ranges, and the dataset is explicitly synthetic.",
        "Do not upload production logs without a privacy and data-handling review.",
        "Validate every high-risk finding with identity, endpoint, network, and change-management context.",
        "Apply containment only through approved incident-response procedures and with human approval.",
    ]:
        st.markdown(f"- {line}")
    _section("Project architecture")
    st.code("""Browser UI (Streamlit)\n        |\n        v\ncybershield.ingest  ->  normalized SecurityEvent records\n        |\n        v\ncybershield.detection  ->  explainable signals + optional Isolation Forest\n        |\n        v\ncybershield.recommendations  ->  bounded defensive follow-up steps\n        |\n        v\ncybershield.reporting  ->  CSV / JSON exports\n\nNo external API calls. No database. No automatic blocking.""", language="text")


_initialise_state()
_source_load_controls()
records, summary, frame = _current_analysis()

with st.sidebar:
    st.markdown("## 🛡️ CyberShield AI")
    st.caption("Security log triage · Local-first")
    page = st.radio("Workspace", ["Command centre", "Event explorer", "Detection lab", "Reports & exports", "About & safety"], label_visibility="collapsed")
    st.markdown("---")
    st.markdown("<span class='cs-chip cs-chip-teal'>LOCAL ANALYSIS</span> <span class='cs-chip cs-chip-violet'>HUMAN REVIEW</span>", unsafe_allow_html=True)
    st.caption(f"{len(st.session_state.raw_events):,} raw events loaded")

if page == "Command centre":
    _overview(records, summary, frame)
elif page == "Event explorer":
    _event_explorer(records, frame)
elif page == "Detection lab":
    _detection_lab(records, summary)
elif page == "Reports & exports":
    _exports(records, summary)
else:
    _about()

st.markdown('<div class="cs-footer">CyberShield AI · Defensive education and analyst support · Findings are indicators, not verdicts. Human review remains essential.</div>', unsafe_allow_html=True)
