import email
from email import policy
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "proton.me", "protonmail.com"
}

BRANDS = [
    "paypal", "microsoft", "google", "apple", "facebook",
    "amazon", "netflix", "bank", "dhl", "fedex"
]

URGENCY_WORDS = [
    "urgent", "verify", "suspended", "limited",
    "security alert", "password", "reset",
    "invoice", "payment", "confirm", "action required"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "rebrand.ly"
}

STATIC_ASSET_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".webp", ".ico", ".woff", ".woff2", ".css"
)


def extract_domain(text):
    m = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", text or "")
    return m.group(1).lower() if m else None


def extract_body_text(msg, raw_email):
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    content = part.get_content()
                    if isinstance(content, str):
                        parts.append(content)
                except Exception:
                    continue
    else:
        try:
            content = msg.get_content()
            if isinstance(content, str):
                parts.append(content)
        except Exception:
            pass

    decoded = "\n".join(parts).strip()
    return decoded if decoded else raw_email


def extract_urls(text):
    raw_urls = re.findall(r"https?://[^\s)>\"'<]+", text or "")
    cleaned = [u.rstrip(".,;:") for u in raw_urls]
    return list(dict.fromkeys(cleaned))


def defang_url(url):
    safe = re.sub(r"^https://", "hxxps://", url, flags=re.IGNORECASE)
    safe = re.sub(r"^http://", "hxxp://", safe, flags=re.IGNORECASE)
    return safe.replace(".", "[.]")


def is_ip_address(host):
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def analyze(raw_email):
    msg = email.message_from_string(raw_email.lstrip(), policy=policy.default)
    findings = []

    from_h = str(msg.get("From") or "").strip()
    reply_h = str(msg.get("Reply-To") or "").strip()
    return_h = str(msg.get("Return-Path") or "").strip()
    subject = str(msg.get("Subject") or "").strip()
    auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))

    from_dom = extract_domain(from_h)
    reply_dom = extract_domain(reply_h)
    return_dom = extract_domain(return_h)

    # SPF / DKIM / DMARC checks
    auth_lower = auth.lower()
    if "spf=fail" in auth_lower:
        findings.append({
            "reason": "SPF failed",
            "points": -25,
            "explanation": (
                "The receiving server recorded 'spf=fail', meaning the server that sent "
                "this email is not authorized by the sender's domain."
            ),
        })
    if "dkim=fail" in auth_lower or "dkim=none" in auth_lower:
        findings.append({
            "reason": "DKIM missing or failed",
            "points": -15,
            "explanation": (
                "The email has a missing or invalid DKIM digital signature, so there is "
                "no cryptographic proof that the message came unaltered from the sender."
            ),
        })
    if "dmarc=fail" in auth_lower:
        findings.append({
            "reason": "DMARC failed",
            "points": -25,
            "explanation": (
                "The email failed DMARC alignment ('dmarc=fail'), which is a strong sign "
                "that the visible sender address may be spoofed."
            ),
        })

    # Header mismatches
    if from_dom and reply_dom and from_dom != reply_dom:
        findings.append({
            "reason": "From and Reply-To domains mismatch",
            "points": -20,
            "explanation": (
                f"The visible From domain ({defang_url(from_dom)}) does not match the "
                f"Reply-To domain ({defang_url(reply_dom)}). Attackers use this so your "
                "replies go to a different inbox they control."
            ),
        })

    if from_dom and return_dom and from_dom != return_dom:
        findings.append({
            "reason": "From and Return-Path mismatch",
            "points": -10,
            "explanation": (
                f"The visible From domain ({defang_url(from_dom)}) differs from the "
                f"technical Return-Path ({defang_url(return_dom)}). This appears in "
                "spoofing, though some legitimate mailing services also do this."
            ),
        })

    # Brand impersonation via free email provider
    if from_dom and from_dom in FREE_EMAIL_DOMAINS:
        for b in BRANDS:
            if b in from_h.lower():
                findings.append({
                    "reason": "Brand impersonation via free email domain",
                    "points": -20,
                    "explanation": (
                        f"The sender name mentions '{b}', but the email was sent from a "
                        f"free personal provider ({defang_url(from_dom)}) instead of an "
                        "official company domain."
                    ),
                })
                break

    # Subject urgency
    matched_urgency = [w for w in URGENCY_WORDS if w in subject.lower()]
    if matched_urgency:
        findings.append({
            "reason": "Urgent / pressure language in subject",
            "points": -8,
            "explanation": (
                f"The subject uses pressure keyword(s): {', '.join(matched_urgency)}. "
                "Phishing emails try to create panic so victims act before verifying."
            ),
        })

    # URL checks (decoded body + deduplicated per unique host)
    body_text = extract_body_text(msg, raw_email)
    urls = extract_urls(body_text)
    defanged_urls = [defang_url(u) for u in urls]

    flagged_ip_hosts = set()
    flagged_deep_hosts = set()
    flagged_shorteners = set()
    flagged_brand_hosts = set()

    for u in urls:
        parsed = urlparse(u)
        host = parsed.netloc.lower().split(":")[0]
        if not host:
            continue

        path = parsed.path.lower()
        clean_host = host.removeprefix("www.")
        safe_host = defang_url(host)

        if is_ip_address(host):
            if host not in flagged_ip_hosts:
                flagged_ip_hosts.add(host)
                findings.append({
                    "reason": "Link uses a raw IP address instead of a domain",
                    "points": -20,
                    "explanation": (
                        f"Found link pointing directly to IP address '{safe_host}'. "
                        "Legitimate companies use named domains, whereas attackers often "
                        "host phishing pages on raw IPs."
                    ),
                })
        elif host.count(".") >= 3 and not path.endswith(STATIC_ASSET_EXTENSIONS):
            if host not in flagged_deep_hosts:
                flagged_deep_hosts.add(host)
                findings.append({
                    "reason": "Suspicious deep subdomain",
                    "points": -5,
                    "explanation": (
                        f"Link host '{safe_host}' has {host.count('.')} dots. Scammers "
                        "sometimes stack subdomains to disguise fake sites (checked once per host)."
                    ),
                })

        if clean_host in URL_SHORTENERS and clean_host not in flagged_shorteners:
            flagged_shorteners.add(clean_host)
            findings.append({
                "reason": f"URL shortener hides destination ({clean_host})",
                "points": -10,
                "explanation": (
                    f"Link uses '{defang_url(clean_host)}', which masks the real "
                    "destination webpage so you cannot inspect it before clicking."
                ),
            })

        for b in BRANDS:
            if b in u.lower() and not host.endswith(f"{b}.com") and (b, host) not in flagged_brand_hosts:
                flagged_brand_hosts.add((b, host))
                findings.append({
                    "reason": f"Deceptive link pretending to be {b}",
                    "points": -12,
                    "explanation": (
                        f"Link mentions '{b}' in '{defang_url(u)}', but the actual "
                        f"website host is '{safe_host}' rather than official '{b}[.]com'."
                    ),
                })

    total_deduction = sum(item["points"] for item in findings)
    score = max(0, min(100, 100 + total_deduction))

    if score <= 40:
        level = "PHISHING (HIGH RISK)"
    elif score <= 70:
        level = "SUSPICIOUS (MEDIUM RISK)"
    else:
        level = "LIKELY LEGIT (LOW RISK)"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "classification": level,
        "risk_score": score,
        "from": from_h,
        "subject": subject,
        "findings": findings,
        "defanged_urls": defanged_urls
    }


def main():
    print("\n=== INTERACTIVE PHISHING CHECKER (OFFLINE) ===")
    print("Paste ONE email (headers + body).")
    print("When finished, type END and press Enter.\n")

    lines = []
    while True:
        line = input(">>> ")
        if line.strip() == "END":
            break
        lines.append(line)

    email_text = "\n".join(lines)

    if not email_text.strip():
        print("\nNo input received. Exiting.")
        return

    report = analyze(email_text)

    print("\n=== RESULT ===")
    print("Classification :", report["classification"])
    print("Risk Score     :", report["risk_score"], "/ 100")
    print("From           :", report["from"])
    print("Subject        :", report["subject"])

    print("\nFindings (Score Breakdown):")
    if report["findings"]:
        for item in report["findings"]:
            print(f"- [{item['points']:>3} pts] {item['reason']}")
            print(f"    Why: {item['explanation']}")
    else:
        print("- No strong indicators (0 pts deducted)")

    if report["defanged_urls"]:
        print("\nDefanged URLs (Safe to View):")
        for u in report["defanged_urls"]:
            print("-", u)

    with open("phishing_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\nSaved -> phishing_report.json")


if __name__ == "__main__":
    main()