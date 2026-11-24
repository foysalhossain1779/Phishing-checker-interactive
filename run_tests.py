from pathlib import Path
import sys
from phish_check import analyze

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"

TEST_CASES = [
    {
        "file": "phish_paypal.eml",
        "expected": "PHISHING (HIGH RISK)",
    },
    {
        "file": "suspicious_reply_mismatch.eml",
        "expected": "SUSPICIOUS (MEDIUM RISK)",
    },
    {
        "file": "legit_store_promo.eml",
        "expected": "LIKELY LEGIT (LOW RISK)",
    },
]


def run_suite():
    passed = 0
    total = len(TEST_CASES)

    print("\n=== PHISHING CHECKER TEST SUITE ===\n")

    for case in TEST_CASES:
        file_path = SAMPLES_DIR / case["file"]

        if not file_path.exists():
            print(f"[FAIL] {case['file']} -> File not found in samples/ folder")
            continue

        raw_email = file_path.read_text(encoding="utf-8", errors="replace")
        report = analyze(raw_email)
        actual = report["classification"]
        expected = case["expected"]

        if actual == expected:
            passed += 1
            print(f"[PASS] {case['file']} | Score: {report['risk_score']:>3}/100 | {actual}")
        else:
            print(f"[FAIL] {case['file']} | Score: {report['risk_score']:>3}/100")
            print(f"       Expected: {expected}")
            print(f"       Actual  : {actual}")

    print(f"\nResult: {passed}/{total} tests passed.")
    return passed == total


if __name__ == "__main__":
    all_passed = run_suite()
    sys.exit(0 if all_passed else 1)