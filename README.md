# CyberShield AI

**A local-first, explainable security-log triage and reporting workbench.**

CyberShield AI ingests structured JSON/JSONL and CSV events plus common OpenSSH authentication logs. It normalizes records, detects repeated failed logins and selected suspicious activity, assigns a bounded explainable risk score, suggests defensive follow-up checks, and exports findings to CSV or JSON. An optional local Isolation Forest model identifies dataset-relative outliers when enough records are available.

> **Important:** this is an academic and portfolio demonstration. It is not a production SIEM, does not automatically block traffic, and does not prove that an event is malicious. The sample data is synthetic and uses documentation-only public IP ranges.

## What is included

```text
CyberShield-AI/
├── app.py                         # Streamlit dashboard and user workflow
├── requirements.txt               # Runtime and test dependencies
├── README.md
├── .env.example                   # No secrets required by this version
├── .streamlit/config.toml          # Light theme and safe upload defaults
├── assets/theme.css               # Warm, multi-colour UI system
├── data/sample_security.jsonl     # Synthetic event dataset for dashboard demo
├── data/sample_auth.log           # Human-readable OpenSSH/syslog example
├── cybershield/
│   ├── config.py                  # Typed input limits and rule thresholds
│   ├── models.py                  # Normalized event and issue data types
│   ├── ingest.py                  # JSON/JSONL, CSV and SSH syslog parsers
│   ├── detection.py               # Explainable scoring and pattern detection
│   ├── anomaly.py                 # Optional unsupervised outlier detection
│   ├── recommendations.py         # Defensive response suggestions
│   ├── reporting.py               # CSV/JSON export functions
│   └── pipeline.py                # Programmatic parse-analyse-summary helper
├── tests/                         # Automated pytest checks
├── docs/ARCHITECTURE.md
├── docs/SECURITY.md
├── REPORT.md                      # Editable report source
└── CyberShield_AI_Report.pdf      # Professional project report
```

## Requirements

- Python 3.10 or newer (Python 3.11 or 3.12 recommended for a smooth dependency experience).
- Internet access only for the first `pip install`; the application itself makes no network/API calls.
- Windows, macOS, or Linux.

## Install and run on Windows (VS Code)

Open the extracted project folder in VS Code. In the integrated terminal, run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

If PowerShell blocks virtual-environment activation, use the virtual environment's executable directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Streamlit prints a local URL, usually `http://localhost:8501`. Open that URL in your browser. The bundled synthetic dataset loads automatically.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

## Run tests

```bash
python -m pytest -q
```

Compile-check the source without launching the UI:

```bash
python -m compileall -q app.py cybershield tests
```

For the command-line parsing and analysis pipeline, from the project directory:

```bash
python - <<'PY'
from pathlib import Path
from cybershield.pipeline import analyse_source

path = Path("data/sample_security.jsonl")
result = analyse_source(path.read_text(encoding="utf-8"), filename=path.name)
print(result["summary"])
print("Top finding:", result["events"][0]["severity"], result["events"][0]["risk_score"])
PY
```

The command may mark dataset-relative outliers differently if dependencies or thresholds change, so use it for a functional demonstration rather than as a fixed performance benchmark.

## Use the dashboard

1. **Command centre:** view event totals, severity distribution, activity over time, and high-scored findings.
2. **Event explorer:** filter by severity, result, event type, account, IP address, host, or message. Select a row to read the evidence and recommendations.
3. **Detection lab:** review detection counts, scoring bands, and the limitations of the anomaly model.
4. **Reports & exports:** download event-level CSV, event-level JSON, or aggregate summary JSON.
5. **About & safety:** review the architecture, intended use, and safe demonstration guidance.

To load another log source, choose a `.json`, `.jsonl`, `.ndjson`, `.csv`, `.log`, or `.txt` file in the sidebar and press **Load selected file**. Supported input formats and mapping details are documented in `docs/ARCHITECTURE.md`.

## Detection approach

Rules generate evidence-linked points, which are summed and capped at 100. Default severity bands are:

| Score | Triage level |
|---:|---|
| 0–24 | Low |
| 25–49 | Guarded |
| 50–74 | High |
| 75–100 | Critical |

Implemented rule families include failed authentication, repeated failed logins from the same source within a configurable 15-minute window, username spraying, a successful login after a nearby failure burst, administrative account involvement, privilege-related events, sensitive file paths, suspicious command strings, and unusual-hours activity. See `docs/ARCHITECTURE.md` for default point values.

The optional Isolation Forest model is fitted to the *currently loaded batch* and uses simple event features. It does not use a labelled training corpus and is not a production-trained detector. A model outlier adds a small score adjustment and an explicit warning; this is a prompt to investigate, not a claim of compromise. Disable it in the sidebar to compare rule-only scoring.

## Privacy and safe defaults

- No external API integrations, telemetry uploads, auto-remediation, or threat-intelligence lookups are used in this version.
- Uploaded logs stay in the running app's memory. The app does not write uploaded source files to disk.
- CSV and JSON exports intentionally include the original message, identifiers, IPs, and findings. Review for secrets and personal data before sharing.
- A 5 MiB upload-size limit and 20,000-record limit prevent unbounded ingestion. Individual text fields are bounded before normalisation.
- Invalid IP fields are left unset and reported as parsing issues. Invalid records are skipped with visible notes where possible.
- Use only logs you own or are authorised to analyse. Do not take containment actions based solely on one score.

## Known limitations

- The input parser supports a practical subset of OpenSSH syslog, not every vendor's log grammar. Unknown raw lines are reported instead of guessed.
- Syslog timestamps do not contain a year or timezone in many deployments. The parser assigns the current UTC year and assumes UTC; adjust this for the source environment before forensic use.
- Rule thresholds are teaching defaults and can create false positives and false negatives. Validate them against a representative, authorised dataset before any operational use.
- The anomaly model uses the current batch as its reference and can shift as the uploaded data changes. There are no published accuracy, precision, recall, or latency claims in this project.
- Recommendations are deterministic analyst prompts, not generated legal/incident-response advice. Human review is required.
- The app is not a multi-user service, long-term log store, alerting service, or enterprise SIEM.

## Academic demonstration checklist

- [ ] Create and activate the Python virtual environment.
- [ ] Install all dependencies from `requirements.txt`.
- [ ] Run `python -m pytest -q` and keep the real terminal output for the report/demo.
- [ ] Start the dashboard using `python -m streamlit run app.py`.
- [ ] Explain that the included events are synthetic and use reserved IP ranges.
- [ ] Show the failed-login burst from `203.0.113.77` and the success-after-failures finding.
- [ ] Open an event and explain how the evidence maps to the score.
- [ ] Toggle the local anomaly model and explain why an outlier is not proof of attack.
- [ ] Upload `data/sample_auth.log` to demonstrate syslog ingestion.
- [ ] Export CSV and JSON, then open both files and inspect the included fields.
- [ ] Present the limitations and proposed validation work honestly.

## Portfolio advice

Before submission, add your own name, institution, department, and date to the PDF/report; include two screenshots from your own run; paste the genuine test output; create your own GitHub repository; and confirm the repository contains no production logs or secrets. Do not claim live production monitoring or a trained threat classifier.

## Licence

Provided for educational demonstration. Add a licence approved by your institution or project team before redistribution.
