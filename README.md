# Offline Phishing Triage Checker

An offline, rule-based phishing triage tool built in Python (CLI + lightweight Flask web app). It inspects raw emails (`.eml`, `.txt`, pasted headers + body, or text-based `.pdf` exports) and outputs a risk score, plain-English explanations for every point deducted, defanged URLs, and Tier-1 SOC next steps.

The project uses transparent heuristics instead of a black-box model so an analyst can verify exactly why an email was flagged during manual triage.

## Project Structure

| File / Folder | Purpose |
| --- | --- |
| `phish_check.py` | Standalone offline detection engine and interactive CLI (Python standard library only) |
| `app.py` | Lightweight Flask web server, PDF text/link extractor, and SOC JSON export route |
| `templates/index.html` | Plain HTML/CSS triage dashboard with no heavy frontend frameworks |
| `run_tests.py` | Automated test script that checks expected risk classifications |
| `samples/` | Sanitized `.eml` test files covering High, Medium, and Low risk emails |
| `requirements.txt` | Optional dependencies for the web interface (`flask`, `pypdf`) |

## What It Checks

- Email Authentication: Parses multi-line `Authentication-Results` headers using Python's built-in `email` module to detect `spf=fail`, `dkim=fail`/`dkim=none`, and `dmarc=fail`.
- Header Consistency: Flags domain mismatches between `From`, `Reply-To`, and `Return-Path`.
- Brand Impersonation: Detects major brand names sent from free consumer email providers (`gmail.com`, `outlook.com`, `yahoo.com`, etc.).
- Social Engineering Signals: Flags urgency and pressure keywords in the subject line and lists the exact words matched.
- URL Inspection: Decodes `quoted-printable` and `base64` MIME bodies cleanly, flags raw IP links, URL shorteners, deceptive brand links, and deep subdomains, and defangs every link (`http://` -> `hxxp://`, `.` -> `[.]`) so nothing is accidentally clickable.
- False-Positive Controls: Deduplicates URL penalties per unique host and excludes static CDN image/font extensions (`.png`, `.jpg` etc.) from the deep-subdomain rule so authenticated marketing emails do not drown analysts in false alerts.
- Tier-1 SOC Workflow: Provides tailored next steps for each risk tier and exports a structured `soc_triage_report.json` file for ticketing or escalation.

## Risk Scoring Model

Analysis starts at `100` and deducts points for each triggered indicator, clamped between `0` and `100`.

| Risk Score | Classification | Triage Meaning |
| --- | --- | --- |
| 0 to 40 | PHISHING (HIGH RISK) | Multiple strong indicators such as auth failures, spoofing, or raw IP/fake brand links |
| 41 to 70 | SUSPICIOUS (MEDIUM RISK) | Moderate red flags requiring out-of-band verification before trusting |
| 71 to 100 | LIKELY LEGIT (LOW RISK) | Few or no offline phishing indicators detected |

## Quickstart

Requires Python 3.9 or newer.

### 1. Create and activate a virtual environment

```bash
python -m venv .venv
```

- Windows (PowerShell): `.venv\Scripts\Activate.ps1`
- Windows (Command Prompt): `.venv\Scripts\activate.bat`
- macOS / Linux: `source .venv/bin/activate`

### 2. Run the Web App (Recommended)

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser and upload any `.eml` file from the `samples/` folder.

### 3. Run the Offline CLI (Zero External Dependencies)

```bash
python phish_check.py
```

Paste raw email headers and body into the terminal, press Enter, type `END`, and press Enter again. Results print to the terminal and save to `phishing_report.json`.

### 4. Run the Sample Test Suite

```bash
python run_tests.py
```

Expected output:

```text
=== PHISHING CHECKER TEST SUITE ===

[PASS] phish_paypal.eml | Score:   0/100 | PHISHING (HIGH RISK)
[PASS] suspicious_reply_mismatch.eml | Score:  62/100 | SUSPICIOUS (MEDIUM RISK)
[PASS] legit_store_promo.eml | Score: 100/100 | LIKELY LEGIT (LOW RISK)

Result: 3/3 tests passed.
```

## Known Limitations and Tradeoffs

This tool is built for offline Tier-1 triage, not as a replacement for an enterprise Secure Email Gateway:

- Lookalike Domains with Valid Authentication: An attacker who registers a lookalike domain (such as `paypa1-support.com`) and sets up valid SPF, DKIM, and DMARC records can still score as Low Risk here. Catching those requires online enrichment (domain age/WHOIS, VirusTotal, or URL reputation feeds).
- Printed PDF Tradeoffs: Printing an email to PDF strips hidden technical headers (`SPF`, `DKIM`, `DMARC`, `Return-Path`), and image-only PDFs (such as Windows Microsoft Print to PDF) cannot be read without OCR. Always prefer raw `.eml` exports when available.
- Static Asset Extension Tradeoff: Skipping image/font extensions (`.png`, `.jpg`) on the low-weight deep-subdomain check removes false positives from real CDNs, though a determined attacker could host a phishing URL ending in `.jpg`. Separating clickable `<a href>` links from `<img src>` tags is a planned improvement.
- No Attachment Analysis: Attached files (`.html`, `.zip`, Office macros, etc.) are not extracted or sandboxed.

