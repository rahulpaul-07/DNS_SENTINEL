"""Convert public datasets into the harness format (domain,label[,family]).

Two modes:

A) Combined labeled CSV (e.g. chrmor/DGA_domains_dataset):
   python -m backend.benchmarks.build_public_benchmark \
       --input dga_domains_full.csv --domain-col domain \
       --label-col class --benign-value legit --family-col subclass

B) Separate benign + malicious lists (e.g. Tranco CSV + a DGA .txt):
   python -m backend.benchmarks.build_public_benchmark \
       --benign-file top-1m.csv --malicious-file dga.txt --max 20000

Writes data/real_benchmark.csv, balanced. Then:
   python -m backend.benchmarks.run_benchmark --benchmark data/real_benchmark.csv
"""
from __future__ import annotations
import argparse, csv, os, random

def _extract_domain(field_or_row):
    # Accept a raw line, or a CSV row where the domain is the field with a dot.
    if isinstance(field_or_row, str):
        parts = [p.strip() for p in field_or_row.replace("\t", ",").split(",")]
    else:
        parts = [str(p).strip() for p in field_or_row]
    cand = [p for p in parts if "." in p and " " not in p]
    return (cand[-1] if cand else parts[-1]).lower().strip()

def from_lines(path, limit):
    out = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            d = _extract_domain(line)
            if d and "." in d:
                out.append(d)
            if limit and len(out) >= limit:
                break
    return out

def from_combined(path, dom, lab, benign_value, fam):
    rows = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for r in csv.DictReader(fh):
            d = (r.get(dom) or "").strip().lower()
            if not d or "." not in d:
                continue
            raw = (r.get(lab) or "").strip().lower()
            label = 0 if raw == benign_value.lower() else 1
            family = (r.get(fam) or ("benign" if label == 0 else "dga")) if fam else ("benign" if label == 0 else "dga")
            rows.append((d, label, family))
    return rows

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input"); ap.add_argument("--domain-col", default="domain")
    ap.add_argument("--label-col", default="class"); ap.add_argument("--benign-value", default="legit")
    ap.add_argument("--family-col", default=None)
    ap.add_argument("--benign-file"); ap.add_argument("--malicious-file")
    ap.add_argument("--max", type=int, default=20000, help="max per class (balanced)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "..", "data", "real_benchmark.csv"))
    a = ap.parse_args()
    rng = random.Random(42)

    if a.input:
        rows = from_combined(a.input, a.domain_col, a.label_col, a.benign_value, a.family_col)
    elif a.benign_file and a.malicious_file:
        b = [(d, 0, "benign") for d in from_lines(a.benign_file, a.max)]
        m = [(d, 1, "dga") for d in from_lines(a.malicious_file, a.max)]
        rows = b + m
    else:
        ap.error("provide --input, or both --benign-file and --malicious-file")

    benign = [r for r in rows if r[1] == 0]
    mal = [r for r in rows if r[1] == 1]
    n = min(len(benign), len(mal), a.max)
    rng.shuffle(benign); rng.shuffle(mal)
    final = benign[:n] + mal[:n]
    rng.shuffle(final)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["domain", "label", "family"]); w.writerows(final)
    print(f"wrote {a.out}: {len(final)} rows ({n} benign / {n} malicious)")

if __name__ == "__main__":
    main()
