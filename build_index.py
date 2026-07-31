"""Stage 1-4 of the pipeline: ingest -> feed lookup -> cross-reference -> score.

Run this once to build data/index.json. Everything downstream (the CLI, the
query layer, the LLM synthesis) reads that file and never touches the network.

Separating index build from query time is deliberate:
  * the CISO's "under 2 minutes" requirement applies to asking questions, not
    to rebuilding the vulnerability corpus;
  * answers become reproducible -- two analysts querying the same index get
    identical numbers, which is a precondition for trusting the tool;
  * the demo does not depend on NVD being up, which it frequently is not.

Usage:
    python build_index.py                # build/refresh from cache + network
    python build_index.py --offline      # cache only, no network calls
"""

import argparse
import json
import os
import sys
from datetime import date, datetime

from vulnintel import catalog, feeds, match, score

ROOT = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(ROOT, "data", "assets.json")
KEV_CACHE = os.path.join(ROOT, "cache", "kev.json")
NVD_CACHE = os.path.join(ROOT, "cache", "nvd")
OUT = os.path.join(ROOT, "data", "index.json")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true",
                    help="use only cached feed data")
    ap.add_argument("--as-of", default=None,
                    help="evaluation date YYYY-MM-DD (default: today)")
    args = ap.parse_args()

    as_of = (datetime.strptime(args.as_of, "%Y-%m-%d").date()
             if args.as_of else date.today())

    with open(ASSETS, "r", encoding="utf-8") as f:
        inventory = json.load(f)
    assets = inventory["assets"]

    declared = inventory.get("metadata", {}).get("asset_count")
    integrity = []
    if declared is not None and declared != len(assets):
        integrity.append(
            f"Inventory metadata declares asset_count={declared} but the file "
            f"contains {len(assets)} asset records. Using the actual records.")

    print(f"[1/4] ingest        : {len(assets)} assets, as-of {as_of}")
    for msg in integrity:
        print(f"      ! {msg}")

    print("[2/4] feeds         : loading CISA KEV ...")
    kev = feeds.fetch_kev(KEV_CACHE, offline=args.offline)
    kev_index = feeds.index_kev(kev)
    print(f"      KEV catalog {kev.get('catalogVersion')} "
          f"({len(kev_index)} exploited CVEs, released {kev.get('dateReleased','')[:10]})")

    nvd = feeds.NvdClient(NVD_CACHE, offline=args.offline)
    n = [0]

    def progress(asset_id, product, version, total):
        n[0] += 1
        got = "LOOKUP FAILED" if total is None else f"{total} CVEs"
        print(f"      [{n[0]:>3}] {asset_id:<12} {product} {version:<18} -> {got}",
              flush=True)

    print("[3/4] cross-reference (NVD CPE applicability + local verification pass)")
    findings, gaps, stats = match.build_findings(assets, nvd, kev_index, progress)

    print(f"[4/4] scoring       : {len(findings)} candidate findings")
    findings = score.score_all(findings, as_of)

    names = {s["name"] for a in assets for s in a["installed_software"]}
    cov = catalog.coverage(names)

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "as_of": as_of.isoformat(),
        "sources": {
            "assets": {
                "file": "data/assets.json",
                "organisation": inventory.get("metadata", {}).get("organisation"),
                "asset_count": len(assets),
            },
            "cisa_kev": {
                "url": feeds.KEV_URL,
                "catalog_version": kev.get("catalogVersion"),
                "date_released": kev.get("dateReleased"),
                "entries": len(kev_index),
            },
            "nist_nvd": {
                "url": feeds.NVD_URL,
                "method": "virtualMatchString CPE applicability query",
                "live_calls_this_run": nvd.calls,
            },
        },
        "coverage": {
            "products_total": len(names),
            "products_mapped": cov["mapped"],
            "products_unmapped": {k: catalog.UNMAPPED_REASONS.get(k, "")
                                  for k in cov["unmapped"]},
            "products_unknown": cov["unknown"],
            "os_matching": "OUT OF SCOPE — see vulnintel/catalog.py for rationale",
        },
        "integrity_notes": integrity,
        "stats": stats,
        "assets": assets,
        "findings": [f.to_dict() for f in findings],
        "coverage_gaps": [g.__dict__ for g in gaps],
    }

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1)

    conf = sum(1 for f in findings if f.confidence == match.CONFIRMED)
    likely = sum(1 for f in findings if f.confidence == match.LIKELY)
    unc = sum(1 for f in findings if f.confidence == match.UNCERTAIN)
    kevc = sum(1 for f in findings if f.in_kev)

    print()
    print(f"  findings   : {len(findings)}  "
          f"(confirmed {conf} / likely {likely} / uncertain {unc})")
    print(f"  KEV-listed : {kevc}")
    print(f"  gaps       : {len(gaps)} software instances not assessed")
    print(f"  wrote      : {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
