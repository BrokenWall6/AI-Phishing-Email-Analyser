"""
Evaluate the detector on a labelled folder of .eml files.

Usage (from the backend folder, venv active):

    python -m tests.evaluate_dataset
    python -m tests.evaluate_dataset --dataset ../datasets/fresh_2026 --offline
    python -m tests.evaluate_dataset --csv evaluation_results.csv

Folder layout:  <dataset>/phishing/*.eml  and  <dataset>/benign/*.eml

The headline numbers are binary: "flagged" means Phishing or Suspicious.
Strict (Phishing only) and lenient (anything but Benign) views are printed
too. Exact duplicates are detected by hash and reported separately.

The AI report is skipped because it does not change the verdict.
--offline turns off WHOIS, DNS and VirusTotal for fast, repeatable runs.
--csv writes one row per email with the component scores.
"""

import argparse
import contextlib
import hashlib
import io
import os
import sys
from collections import Counter
from pathlib import Path

POSITIVE_VERDICTS = {"Phishing", "Suspicious"}
evaluation = None  # imported in main() after env setup


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", default="../datasets/public_2026")
    parser.add_argument("--csv", default=None, help="write per-email results to this CSV file")
    parser.add_argument("--offline", action="store_true", help="disable WHOIS/DNS/VirusTotal lookups")
    parser.add_argument("--quiet", action="store_true", help="only print the final report")
    return parser.parse_args()


def metrics(rows, is_positive):
    tp = sum(1 for r in rows if r["expected"] == "Phishing" and is_positive(r["predicted"]))
    fn = sum(1 for r in rows if r["expected"] == "Phishing" and not is_positive(r["predicted"]))
    tn = sum(1 for r in rows if r["expected"] == "Benign" and not is_positive(r["predicted"]))
    fp = sum(1 for r in rows if r["expected"] == "Benign" and is_positive(r["predicted"]))

    total = tp + fn + tn + fp
    accuracy = (tp + tn) / total * 100 if total else 0
    precision = tp / (tp + fp) * 100 if tp + fp else 0
    recall = tp / (tp + fn) * 100 if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    fpr = fp / (fp + tn) * 100 if fp + tn else 0

    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "accuracy": accuracy,
            "precision": precision, "recall": recall, "f1": f1, "fpr": fpr, "n": total}


def print_metrics(title, m):
    print(title)
    print("-" * 70)
    print(f"  Emails: {m['n']}   TP={m['TP']}  FP={m['FP']}  TN={m['TN']}  FN={m['FN']}")
    print(f"  Accuracy  : {m['accuracy']:.2f}%")
    print(f"  Precision : {m['precision']:.2f}%")
    print(f"  Recall    : {m['recall']:.2f}%")
    print(f"  F1 score  : {m['f1']:.2f}%")
    print(f"  False-positive rate: {m['fpr']:.2f}%")
    print()


def main():
    args = parse_args()

    if args.offline:
        os.environ["ENABLE_NETWORK_LOOKUPS"] = "false"

    # Import after setting env so settings pick it up.
    from app.services.analysis_service import AnalysisService
    global evaluation
    from app.services import evaluation

    service = AnalysisService()
    dataset = Path(args.dataset)

    files = [("Phishing", p) for p in sorted((dataset / "phishing").glob("*.eml"))]
    files += [("Benign", p) for p in sorted((dataset / "benign").glob("*.eml"))]

    if not files:
        print(f"No .eml files found under {dataset}/phishing and {dataset}/benign")
        sys.exit(1)

    rows = []
    errors = []
    seen_hashes = {}

    for index, (expected, path) in enumerate(files, start=1):

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        duplicate_of = seen_hashes.get(digest)
        seen_hashes.setdefault(digest, path.name)

        try:
            with contextlib.redirect_stdout(io.StringIO()):
                result = service.analyze_email(str(path), include_ai_report=False)
        except Exception as exc:  # keep going, report at the end
            errors.append((path.name, repr(exc)))
            continue

        row = evaluation.result_to_row(path.name, expected, result, duplicate_of)
        rows.append(row)

        if not args.quiet:
            mark = "OK " if (expected == "Phishing") == (row["predicted"] in POSITIVE_VERDICTS) else "ERR"
            print(f"[{index:3}/{len(files)}] {mark} {expected:8} -> {row['predicted']:10} "
                  f"score={row['risk_score']:3}  {path.name}")

    unique_rows = [r for r in rows if not r["duplicate_of"]]

    print()
    print("=" * 70)
    print("FINAL EVALUATION RESULTS")
    print("=" * 70)
    print(f"Dataset: {dataset}")
    print(f"Files: {len(files)}   processed: {len(rows)}   errors: {len(errors)}   "
          f"exact duplicates: {len(rows) - len(unique_rows)}")
    print(f"Network lookups: {'OFF' if args.offline else 'ON'}")
    print()

    print_metrics("Binary (flagged = Phishing or Suspicious)", metrics(rows, lambda v: v in POSITIVE_VERDICTS))
    print_metrics("Binary, unique emails only", metrics(unique_rows, lambda v: v in POSITIVE_VERDICTS))
    print_metrics("Strict (flagged = Phishing only)", metrics(rows, lambda v: v == "Phishing"))
    print_metrics("Lenient (flagged = anything except Benign, i.e. score >= 20)",
                  metrics(rows, lambda v: v != "Benign"))

    print("Verdict distribution")
    print("-" * 70)
    for label in ("Phishing", "Benign"):
        dist = Counter(r["predicted"] for r in rows if r["expected"] == label)
        print(f"  expected {label:8}: " + ", ".join(f"{k}={v}" for k, v in dist.most_common()))
    print()

    print("Misclassified (binary)")
    print("-" * 70)
    for r in rows:
        if (r["expected"] == "Phishing") != (r["predicted"] in POSITIVE_VERDICTS):
            print(f"  {r['expected']:8} -> {r['predicted']:10} score={r['risk_score']:3} "
                  f"{r['file']}  [{r['top_findings'][:90]}]")

    if errors:
        print()
        print("Errors")
        print("-" * 70)
        for name, err in errors:
            print(f"  {name}: {err}")

    if args.csv:
        evaluation.write_csv(args.csv, rows)
        print(f"\nPer-email results written to {args.csv}")


def evaluate_dataset():
    """Backwards-compatible entry point."""
    main()


if __name__ == "__main__":
    main()
