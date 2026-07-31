"""CLI: ask natural-language questions about the fleet's vulnerability exposure.

    python ask.py "what should we patch first?"
    python ask.py --show-plan "which Finance assets are actively exploited?"
    python ask.py --llm "summarise our posture for the CISO"
    python ask.py --benchmark          # run all 10 assignment questions

Default mode is fully deterministic: keyword router -> query engine ->
templated answer. `--llm` swaps the planner and narrator for Claude and then
runs the citation verifier over the generated prose.
"""

import argparse
import json
import os
import sys
import time

from vulnintel import answer, llm, query

ROOT = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(ROOT, "data", "index.json")

BENCHMARK = [
    "Which of our assets have critical unpatched CVEs?",
    "What is our highest-risk server right now and why?",
    "Which software package should we patch first to reduce the most exposure across the fleet?",
    "How many of our Finance department assets are affected by actively exploited vulnerabilities?",
    "Are any of our assets running software with a CISA KEV due date that has already passed?",
    "Summarise our overall vulnerability posture for the CISO in 3 sentences.",
    "Which business unit has the most critical exposure?",
    "What would patching Apache HTTP Server on all affected hosts reduce our CVE count by?",
    "List all CVEs affecting our network devices sorted by CVSS score.",
    "Are there any assets that have not been scanned in the last 30 days that also have high-severity CVEs?",
]

BANNER = "=" * 78


def load_index() -> dict:
    if not os.path.exists(INDEX):
        sys.exit(f"No index found at {INDEX}.\nRun:  python build_index.py")
    with open(INDEX, "r", encoding="utf-8") as f:
        return json.load(f)


def run_one(engine: query.Engine, index: dict, question: str,
            use_llm: bool, show_plan: bool) -> None:
    t0 = time.time()

    # --- stage 1: plan -----------------------------------------------------
    if use_llm:
        try:
            spec = llm.plan(question)
        except Exception as e:
            print(f"  ! LLM planner unavailable ({e}); using deterministic router.")
            spec = query.route(question)
    else:
        spec = query.route(question)

    # --- stage 2: execute (always deterministic) ---------------------------
    result = engine.run(spec)

    # --- stage 3: render ---------------------------------------------------
    text = answer.render(result)

    print(BANNER)
    print(f"Q: {question}")
    print(BANNER)
    if show_plan:
        print(f"[plan:{spec.planner}] {spec.interpretation or query._describe(spec)}")
        print(f"[matched] {result['matched_findings']} finding(s)")
        print("-" * 78)

    if use_llm:
        try:
            prose = llm.narrate(question, result, text)
            ok, problems = llm.verify_narration(prose, result, index)
            print(prose)
            print()
            if ok:
                print("  [verifier] PASS - every CVE and asset cited appears in the "
                      "evidence set.")
            else:
                print("  [verifier] FAIL - generated text references data not in the "
                      "evidence set:")
                for p in problems:
                    print(f"    ! {p}")
                print("  Falling back to the deterministic answer:")
                print()
                print(text)
        except Exception as e:
            print(f"  ! LLM narrator unavailable ({e}); deterministic answer:")
            print()
            print(text)
    else:
        print(text)

    print()
    print(f"  [{time.time() - t0:.2f}s]  source: CISA KEV "
          f"{index['sources']['cisa_kev']['catalog_version']} + NIST NVD; "
          f"index built {index['generated_at']}")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("question", nargs="*", help="natural-language question")
    ap.add_argument("--llm", action="store_true",
                    help="use Claude for planning and narration (needs ANTHROPIC_API_KEY)")
    ap.add_argument("--show-plan", action="store_true",
                    help="print the QuerySpec the question compiled to")
    ap.add_argument("--benchmark", action="store_true",
                    help="run the 10 assignment questions")
    args = ap.parse_args()

    index = load_index()
    engine = query.Engine(index)

    if args.llm and not llm.available():
        print("  ! --llm requested but no ANTHROPIC_API_KEY / anthropic package "
              "found. Running deterministically.\n")
        args.llm = False

    if args.benchmark:
        print(f"\nFleet: {index['sources']['assets']['organisation']}")
        print(f"Assets: {index['sources']['assets']['asset_count']}  |  "
              f"Findings: {len(index['findings'])}  |  "
              f"KEV catalog: {index['sources']['cisa_kev']['catalog_version']}  |  "
              f"as of {index['as_of']}\n")
        for q in BENCHMARK:
            run_one(engine, index, q, args.llm, args.show_plan)
        return 0

    if not args.question:
        ap.print_help()
        return 1

    run_one(engine, index, " ".join(args.question), args.llm, args.show_plan)
    return 0


if __name__ == "__main__":
    sys.exit(main())
