"""Generate a family-stratified DGA vs. benign benchmark (seeded, reproducible).

This is a deliberately *harder* and larger evaluation set than the bundled
training data. It is generated from published DGA *patterns* — not scraped from
any single named corpus — so no external download is required and results are
fully reproducible. The harness (run_benchmark.py) also accepts real external
CSVs (CIC-Bell-DNS-EXF-2021, Tranco, Bambenek), so the same evaluation can be
run on recognized public data by dropping those files in.

Malicious families (label 1):
  - random      : uniform [a-z0-9] strings (Conficker / ramnit / cryptolocker class)
  - arithmetic  : LCG-seeded character selection (large class of arithmetic DGAs)
  - hex         : long hex strings (base16-style tunneling / exfil subdomains)
  - dictionary  : concatenated real words (suppobox / matsnu / gozi class) — the HARD case

Benign (label 0):
  - real English single/two-word domains + a set of well-known real domains
"""
from __future__ import annotations
import argparse, csv, random, string

SEED = 1337
TLDS = ["com", "net", "org", "info", "biz", "io", "co", "xyz", "online", "site"]

# Embedded real-English wordlist (common words) — keeps the benchmark self-contained.
WORDS = ("time year people way day man thing woman life child world school state "
 "family student group country problem hand part place case week company system "
 "program question work government number night point home water room mother area "
 "money story fact month lot right study book eye job word business issue side kind "
 "head house service friend father power hour game line end member law car city "
 "community name president team minute idea body information back parent face others "
 "level office door health person art war history party result change morning reason "
 "research girl guy moment air teacher force education market cloud data secure network "
 "bright quick smart green blue rapid prime alpha delta nova pixel stream vault forge "
 "north south east west river stone light shadow iron gold silver copper maple cedar "
 "harbor summit valley meadow orchard beacon anchor compass lantern harvest garden "
 "market shop store trade goods craft build make design plan launch scale grow ship "
 "phoenix atlas orbit comet lunar solar amber coral crystal granite marble willow "
 "falcon eagle otter panda tiger lion wolf bear hawk raven finch heron swift crane").split()
WORDS = sorted(set(WORDS))

REAL_DOMAINS = ("google.com github.com amazon.com microsoft.com cloudflare.com wikipedia.org "
 "netflix.com slack.com apple.com facebook.com youtube.com reddit.com linkedin.com "
 "stackoverflow.com nytimes.com bbc.co.uk spotify.com dropbox.com adobe.com nvidia.com "
 "intel.com samsung.com qualcomm.com goldmansachs.com paypal.com stripe.com twitch.tv "
 "wordpress.com shopify.com salesforce.com oracle.com ibm.com cisco.com vmware.com "
 "atlassian.com gitlab.com bitbucket.org medium.com quora.com pinterest.com").split()


def _rand_tld(rng): return rng.choice(TLDS)

def gen_random(rng):
    n = rng.randint(12, 22)
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n)) + "." + _rand_tld(rng)

def gen_arithmetic(rng):
    # Linear congruential generator picking characters — mirrors many arithmetic DGAs.
    seed = rng.randint(1, 2**31 - 1)
    a, c, m = 1103515245, 12345, 2**31
    chars = string.ascii_lowercase
    out = []
    for _ in range(rng.randint(12, 20)):
        seed = (a * seed + c) % m
        out.append(chars[seed % 26])
    return "".join(out) + "." + _rand_tld(rng)

def gen_hex(rng):
    n = rng.randint(16, 32)
    label = "".join(rng.choice("0123456789abcdef") for _ in range(n))
    return f"{label}." + _rand_tld(rng)

def gen_dictionary(rng):
    k = rng.choice([2, 2, 3])            # 2-3 real words concatenated
    sep = rng.choice(["", "", "-"])
    return sep.join(rng.choice(WORDS) for _ in range(k)) + "." + _rand_tld(rng)

def gen_benign(rng):
    r = rng.random()
    if r < 0.20:
        return rng.choice(REAL_DOMAINS)                       # real, well-known
    if r < 0.60:
        return rng.choice(WORDS) + "." + _rand_tld(rng)       # single real word
    sep = rng.choice(["", "-", ""])
    return rng.choice(WORDS) + sep + rng.choice(WORDS) + "." + _rand_tld(rng)  # two-word

FAMILIES = {"random": gen_random, "arithmetic": gen_arithmetic, "hex": gen_hex, "dictionary": gen_dictionary}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-family", type=int, default=1500, help="malicious domains per DGA family")
    ap.add_argument("--out", default="data/dga_benchmark.csv")
    a = ap.parse_args()
    rng = random.Random(SEED)
    rows, seen = [], set()

    for fam, fn in FAMILIES.items():
        made = 0
        while made < a.per_family:
            d = fn(rng)
            if d in seen:
                continue
            seen.add(d); rows.append((d, 1, fam)); made += 1

    n_benign = a.per_family * len(FAMILIES)   # balanced
    made = 0
    while made < n_benign:
        d = gen_benign(rng)
        if d in seen:
            continue
        seen.add(d); rows.append((d, 0, "benign")); made += 1

    rng.shuffle(rows)
    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["domain", "label", "family"]); w.writerows(rows)
    print(f"wrote {a.out}: {len(rows)} rows "
          f"({sum(r[1] for r in rows)} malicious across {len(FAMILIES)} families, "
          f"{sum(1 for r in rows if r[1]==0)} benign)")


if __name__ == "__main__":
    main()
