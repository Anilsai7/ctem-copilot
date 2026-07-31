# CTEM Exposure Copilot

Ask natural-language questions about a fleet's vulnerability exposure and get a
grounded, cited, prioritised answer.

Built against the provided synthetic inventory (23 assets, 5 business units)
cross-referenced with the live **CISA KEV** catalog and **NIST NVD**.

```bash
python build_index.py                 # one-time: fetch feeds, build the index
python ask.py --benchmark             # run the 10 assignment questions
python ask.py "what should we patch first?"
python ask.py --show-plan "how many Finance assets are actively exploited?"
```

No dependencies. Standard library only, Python 3.8+. The LLM layer is optional
(`--llm`, needs `pip install anthropic` and `ANTHROPIC_API_KEY`); everything
works without it.

---

## The problem this is solving

The client's scanner produced 3,400 findings and the security team started
ignoring it. That is not a data problem — the data was correct. It is a
*prioritisation and trust* problem:

1. No ranking, so there was no answer to "what do we do Monday morning".
2. No business context, so a critical CVE on a test box outranked a real one.
3. No explanation, so nobody could tell whether a finding deserved the panic.

Adding an LLM to that pipeline could easily make it worse: a system that
*sounds* authoritative and occasionally invents a CVE is more dangerous than a
spreadsheet nobody reads. So the design starts from the trust question.

---

## Architecture

```
  assets.json ─┐
               ├─► ingest ──► cross-reference ──► score ──► index.json
  CISA KEV ────┤             (deterministic)   (deterministic)     │
  NIST NVD ────┘                                                   │
                                                                   ▼
   "what should we patch first?" ──► PLAN ──► QuerySpec ──► EXECUTE ──► rows+facts
                                    (LLM or                (deterministic)   │
                                     rules)                                  ▼
                                                              NARRATE ──► VERIFY ──► answer
                                                              (LLM or       (never
                                                              template)      an LLM)
```

**The load-bearing decision: the LLM never touches a number.**

The model does two jobs — turn a question into a typed `QuerySpec`, and write
prose over rows that Python already computed. It cannot invent a CVE ID,
because the spec has no field for one, and the narration is checked afterwards.

| Stage | Who does it | Why |
|---|---|---|
| Version → CVE applicability | NVD CPE ranges + local comparator | Reproducible, auditable |
| Exploitation status, due dates | CISA KEV | Authoritative |
| Risk scoring | Transparent additive formula | Arguable — a client can change the weights |
| NL → QuerySpec | Claude (or keyword rules) | Genuinely ambiguous, LLMs are good at it |
| Rows → prose | Claude (or templates) | Genuinely a language task |
| Citation check | Regex over the evidence set | An LLM cannot be its own auditor |

### Division of authority between the two feeds

This matters and is easy to get wrong:

- **KEV** tells you a CVE is being exploited and when CISA requires it fixed.
  It carries **no CVSS score and no version ranges** — so KEV alone *cannot*
  tell you whether *your* Apache is affected. Matching on KEV product names
  produces false positives.
- **NVD** carries CVSS and, critically, CPE version applicability. Asking NVD
  `virtualMatchString=cpe:2.3:a:apache:log4j:2.14.1` makes NVD itself decide
  whether that exact version is in range.

So: **NVD decides whether it applies, KEV decides how urgent it is.**

### The verification pass

Every CVE NVD returns is *independently re-checked* locally against the raw CPE
ranges using our own version comparator. Two signals per finding:

| NVD says | Local re-check | Confidence |
|---|---|---|
| applicable | confirms | `CONFIRMED` |
| applicable | inconclusive | `LIKELY` (surfaced, ranked lower) |
| applicable | contradicts | `UNCERTAIN` (flagged as a conflict) |

The point isn't that our comparator beats NVD's. It's that when two methods
disagree, the analyst sees the disagreement instead of a single confident
number.

---

## Risk scoring

Transparent and additive, 0–100, so "why is this number one" is a sentence:

| Component | Max | Rationale |
|---|---:|---|
| CVSS severity | 30 | Capped — CVSS alone is what produced the unusable 3,400-item list |
| Exploitation (KEV) | 30 | Weighted equal to severity: a 7.5 under active attack beats a theoretical 9.8 |
| Asset criticality | 25 | Business impact |
| Remediation urgency | 15 | CISA due date / overdue |

Every finding carries its own `score_rationale` — the sentences that produced
the number. Confidence is applied as a ranking weight and reported separately,
so an uncertain finding is never presented as fact.

**Known gap:** network exposure (internet-facing vs. internal) is one of the
strongest real prioritisation signals and is absent from the inventory, so it
contributes nothing here.

---

## Handling ambiguity honestly

The system distinguishes *"we checked and you're clean"* from *"we did not
check"* — conflating those is how vulnerability programmes lose credibility.

- Products with no CPE mapping are reported as **coverage gaps with reasons**,
  never as zero findings. Ask: `python ask.py "what did you not assess?"`
- **Java SE** is deliberately unmapped: NVD uses `1.8.0:update_271`, the
  inventory says `8.0.271`. Guessing would produce confident-but-wrong
  applicability, so it is flagged for manual review instead.
- **Operating systems are out of scope** — querying NVD for "Windows Server
  2019" returns hundreds of CVEs and recreates the noise problem. OS patching
  also runs on a different workflow (WSUS/MECM/Satellite). Stated everywhere,
  not hidden.
- The inventory metadata claims `asset_count: 23` and contains 23 records; any
  mismatch is surfaced as a data-integrity note rather than silently accepted.

---

## Trust & hallucination — where this can still fail

Honest list:

1. **The CPE mapping is hand-curated.** A wrong mapping produces confidently
   wrong findings. It's the largest systematic risk and the reason it's a
   reviewable table rather than a fuzzy matcher.
2. **NVD's CPE data is imperfect.** Vendors under- and over-declare affected
   ranges. We inherit that.
3. **Inventory accuracy is assumed.** If the CMDB says 2.4.49 and the box runs
   2.4.58, every downstream conclusion is wrong. Real deployments need
   authenticated scan data, not an inventory export.
4. **The verifier checks citations, not reasoning.** It catches an invented CVE
   ID. It cannot catch prose that cites real CVEs but characterises them
   misleadingly.
5. **No exploit-prediction signal.** EPSS would materially improve ranking of
   non-KEV findings.

---

## What I'd do next

**With another day:** add EPSS scores; add internet-exposure as a scoring
input; expand the CPE catalog with a confidence rating per mapping; export to
ServiceNow-ready change tickets grouped by patch action rather than by CVE.

**With another week:** replace the hand-curated catalog with reconciliation
against authenticated scanner output (Tenable/Qualys already resolve CPEs);
add exception management with expiry and owner; build the exposure-over-time
trend the CISO actually wants ("how has our exposure changed?" currently has
no answer because there's only one snapshot); add attack-path reasoning so
"this workstation is one hop from the DC" affects the ranking.

---

## Who this is for

Today it is best suited to a **vulnerability-management analyst or CTEM lead**
preparing a remediation sprint — someone who can sanity-check the CPE mappings
and wants the cross-referencing and ranking done for them.

It is *not* yet an autonomous CISO dashboard: the coverage gaps require a human
who understands what "we didn't assess Java SE" implies. The CISO-facing output
(`posture_summary`) is designed to be handed *up* by that analyst, not
self-served.

---

## Layout

```
build_index.py        pipeline driver: ingest -> feeds -> cross-ref -> score
ask.py                CLI
vulnintel/
  catalog.py          inventory name -> CPE mapping + documented coverage gaps
  feeds.py            KEV + NVD clients (cache, retry, rate limit, TLS trust)
  versions.py         version parsing/comparison (OpenSSL letters, Cisco, etc.)
  match.py            cross-reference + independent verification pass
  score.py            explainable risk model
  query.py            QuerySpec + deterministic router + execution engine
  answer.py           templated rendering with citations
  llm.py              optional Claude planner/narrator + citation verifier
data/index.json       built artifact — every answer reads only from here
cache/                KEV + NVD responses (offline-capable demo)
```

Index build and query time are separated on purpose: the CISO's "under two
minutes" applies to asking questions, not to rebuilding a vulnerability corpus,
and it makes answers reproducible — two analysts querying the same index get
identical numbers.
