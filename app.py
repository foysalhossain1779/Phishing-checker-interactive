import json
from flask import Flask, Response, render_template, request
from pypdf import PdfReader
from phish_check import analyze

app = Flask(__name__)


def extract_pdf_text(file_stream):
    reader = PdfReader(file_stream)
    parts = []

    for page in reader.pages:
        parts.append(page.extract_text() or "")
        for annot in page.get("/Annots") or []:
            obj = annot.get_object()
            action = obj.get("/A")
            if action:
                action_obj = action.get_object() if hasattr(action, "get_object") else action
                uri = action_obj.get("/URI")
                if uri:
                    parts.append(str(uri))

    full_text = "\n".join(parts)

    header_lines = [
        line.strip()
        for line in full_text.splitlines()
        if line.lower().startswith(("from:", "subject:", "reply-to:", "return-path:"))
    ]
    if header_lines:
        return "\n".join(header_lines) + "\n\n" + full_text
    return full_text


def get_recommended_actions(report):
    score = report["risk_score"]

    if score <= 40:
        return [
            "Do NOT click any links, download attachments, or reply to the sender.",
            "Quarantine or delete the message and search mail logs for other recipients.",
            "Inspect the defanged URLs in a sandbox or reputation tool (e.g., urlscan.io or VirusTotal).",
            "If a user interacted with the email, reset credentials immediately and revoke active sessions.",
        ]
    if score <= 70:
        return [
            "Treat the message with caution and avoid clicking links until verified.",
            "Verify the sender out-of-band using a trusted phone number or channel (do not hit Reply).",
            "Review full email headers and check defanged URLs against threat intelligence feeds.",
        ]
    return [
        "No strong phishing indicators were detected by offline heuristics.",
        "Still verify unexpected payment, invoice, or login requests—lookalike domains can pass SPF/DKIM/DMARC.",
        "Close the triage ticket as benign if the sender and business context are expected.",
    ]


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None
    warning = None
    actions = []
    report_json = ""
    pasted_email = ""

    if request.method == "POST":
        uploaded_file = request.files.get("eml_file")
        pasted_email = request.form.get("email_text", "")
        raw_email = ""

        if uploaded_file and uploaded_file.filename:
            filename = uploaded_file.filename.lower()
            if filename.endswith(".pdf"):
                try:
                    raw_email = extract_pdf_text(uploaded_file.stream)
                    warning = (
                        "PDF mode: Printed emails strip hidden technical headers "
                        "(SPF, DKIM, DMARC, Return-Path), so only visible text and links "
                        "were checked. Upload a .eml file for full header analysis."
                    )
                except Exception:
                    error = "Could not read this PDF file. Please make sure it is not corrupted or password-protected."
            else:
                raw_email = uploaded_file.read().decode("utf-8", errors="replace")
        else:
            raw_email = pasted_email

        if not error:
            if not raw_email.strip():
                error = "No readable text found. Please paste an email or upload a .eml, .txt, or text-based .pdf file."
            else:
                report = analyze(raw_email)
                actions = get_recommended_actions(report)
                triage_package = {
                    "tool": "Offline Phishing Triage Checker",
                    "analysis_mode": "pdf_partial" if warning else "full_email",
                    "warning": warning,
                    "report": report,
                    "recommended_actions": actions,
                }
                report_json = json.dumps(triage_package)

    return render_template(
        "index.html",
        report=report,
        error=error,
        warning=warning,
        actions=actions,
        report_json=report_json,
        pasted_email=pasted_email,
    )


@app.route("/export", methods=["POST"])
def export_report():
    raw_json = request.form.get("report_json", "")
    if not raw_json:
        return "No report data to export.", 400

    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError:
        return "Invalid report data.", 400

    pretty_json = json.dumps(parsed, indent=2)
    return Response(
        pretty_json,
        mimetype="application/json",
        headers={
            "Content-Disposition": "attachment; filename=soc_triage_report.json"
        },
    )


if __name__ == "__main__":
    app.run(debug=True)