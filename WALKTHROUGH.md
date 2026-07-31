# Walkthrough

*Deliverable 2 — what I built, the decisions behind it, and what I'd do next.*
*Written to be read without me in the room.*

---

## 1. What it does (30 seconds)

Ask a plain-English question about the fleet's vulnerability exposure; get a
ranked, cited, actionable answer.

```bash
pip install -r requirements.txt
streamlit run app.py       # UI
python solve.py            # same answers as a CLI report, zero dependencies
```

**On this dataset:** 23 assets → **39 findings** (26 confirmed / 8 likely /
5 uncertain), **26 on CISA KEV**, **26 past their federal deadline**, worst
single item **CVE-2021-44228 on FIN-SRV-002 at 100/100**.

---

## 2. The problem I was actually solving

The brief says the client's scanner returned 3,400 findings with no
prioritisation and the security team started ignoring it.

That is **not a data problem**. The findings were real. It is a *prioritisation
and trust* problem, and it has three parts:

1. No ranking → no answer to "what do we do Monday".
2. No business context → a critical CVE on a test box outranked a real one.
3. No explanation → nobody could tell which findings deserved the panic.

The way to make that **worse** is to add an LLM that sounds authoritative and
occasionally invents a CVE. So every architectural decision below flows from
one question: *would a sceptical analyst trust this enough to act on it?*

---

## 3. The decision I'd most want to be asked about

**I built the obvious solution first, measured it, and threw it away.**

The natural approach is to query NVD by CPE for every installed package. I
built that — it's still in the repo (`vulnintel/`, `build_index.py`). It works.
It returned:

| | |
|---|---|
| Findings | **14,080** |
| Chrome 114 alone | **2,279 CVEs** |
| Distinct CVEs | 5,293 |

Every one of those Chrome CVEs is *technically correct*: Chrome 114 in 2026 is
~40 releases behind, so every CVE fixed in any later release genuinely applies.

And it is **operationally useless**. I had reproduced the client's
3,400-finding problem four times over.

So I inverted the approach: **curated rules with explicit version ranges, each
one read from NVD's CPE data**, scoped to high-signal packages. 39 findings a
patching team can actually work.

**Precision over recall, deliberately.** I'd rather defend 39 findings that are
all real than 14,080 that are all true.

---

## 4. Architecture

```
  assets.json ──┐
                ├──► match ──► score ──► answer
  CISA KEV ─────┘     │          │         │
   (live feed)        ▼          ▼         ▼
                 confidence  confidence  citations
                    tier      weighting  + caveats

  question ──► ROUTE ──► [engine] ──► NARRATE ──► VERIFY ──► answer
               LLM or                 LLM or      never
               keywords               templates   an LLM
```

### Where AI is used

| Stage | Who | Why |
|---|---|---|
| Version → CVE applicability | Python | Reproducible, checkable |
| KEV status, due dates | Live CISA feed | Authoritative |
| Risk scoring | Transparent formula | Auditable and arguable |
| **Question → intent** | **Claude** or keyword router | Genuinely ambiguous |
| **Rows → prose** | **Claude** or templates | Genuinely a language task |
| **Citation audit** | **Regex, no LLM** | A model can't audit itself |

### Where AI is deliberately **not** used

**Nothing that produces a number.** Not matching, not scoring, not KEV lookup,
not date arithmetic.

*An LLM that cannot reach the numbers cannot get the numbers wrong.*

Two analysts running the same query get identical output. That reproducibility
is a precondition for a CISO signing a remediation sprint.

### The verifier (`llm_layer.verify`)

Every generated answer is scanned for CVE IDs, asset IDs and CVSS scores; each
is checked against the evidence rows the engine computed. Unsupported reference
→ answer **rejected**, deterministic answer shown, rejected text kept visible.

Tested against a deliberately fabricated sentence — it caught all three
inventions (bad CVE, bad asset, bad CVSS).

### Graceful degradation

With no API key, all 12 questions still work via keyword routing and templates.
**The LLM is an enhancement, never a dependency.** A security tool that stops
working when an external API is down is not a security tool.

---

## 5. Confidence tiers — the feature I'd defend hardest

Version applicability and exploitability are **not the same claim**, and
collapsing them is how tools lose credibility.

| Tier | Meaning | Weight |
|---|---|---:|
| `confirmed` | Version in affected range; nothing else required | ×1.00 |
| `likely` | Version affected, but exploitation needs config the inventory lacks | ×0.85 |
| `uncertain` | A load-bearing precondition is unproven, or the data contradicts itself | ×0.70 |

**Worked example.** Cisco IOS XE 16.9.4 on `OPS-NET-001` matches
`CVE-2023-20198` — CVSS **10.0**, KEV-listed, overdue. But that exploit needs
the HTTP Web UI *enabled and reachable from an untrusted network*, and the
inventory records neither.

Scored naively it would rank #1. It scores **66/100** and is labelled
`uncertain` with the reason attached. It is surfaced, not hidden — an analyst
can verify in five minutes and promote it.

---

## 6. Scoring

| Component | Max | Rationale |
|---|---:|---|
| CVSS severity | 30 | **Capped** — CVSS alone produced the unusable 3,400 list |
| Exploitation (KEV) | 30 | Equal to severity: a 7.5 under attack beats a theoretical 9.8 |
| Asset criticality | 25 | Business impact |
| Deadline urgency | 15 | CISA due-date proximity / overdue |

Subtotal × confidence weight. Every finding carries its own `score_rationale`.

**Known gap, stated in the tool:** internet-facing vs internal is one of the
strongest real prioritisation signals and is **absent from the inventory**. It
contributes nothing. The tool does not invent it.

---

## 7. Data-quality checks — run before any finding is trusted

The inventory is audited first:

- 🔴 **`IT-SRV-003` reports Ubuntu 18.04 but lists Veeam Backup & Replication**,
  which is Windows-only server software. Findings for it are **automatically
  downgraded to `uncertain`**.
- 🟠 **7 assets have `last_scan_date` after `metadata.generated_date`** — scans
  dated after the export that contains them.
- 🟡 The brief describes 25 assets; the file contains 23.

I flag these because a tool that reports confidently on contradictory input is
worse than one that says "check your CMDB".

---

## 8. Shortcuts I took

| Shortcut | Why | Cost |
|---|---|---|
| Curated rules, not full NVD | Full NVD = 14,080 findings | 32 of 47 packages unassessed — **reported, never silently** |
| OS patching out of scope | Separate Patch-Tuesday/WSUS workflow; would re-add hundreds of CVEs | OS risk invisible here |
| One browser CVE, not all | Chrome alone was 2,279 | Other browser CVEs missed |
| Java SE via vendor advisory | NVD's CPE is `oracle:jre:1.8.0` — no update granularity | Marked `uncertain`, cannot be machine-verified |
| Keyword router, not LLM-only | Works with no API key | Less flexible than pure NL |

Every one is surfaced in the **Data quality & limits** tab. *Absence of a
finding is never presented as evidence of safety.*

---

## 9. Where it can still fail

1. **Curated rules are the biggest systematic risk.** Every range was read from
   NVD CPE nodes, but a wrong rule produces a confidently wrong finding.
2. **Inventory accuracy is assumed.** If the CMDB says 2.4.49 and the host runs
   2.4.58, everything downstream is wrong. Production needs authenticated scan data.
3. **Confidence tiers encode judgement, not measurement.** `likely` is my reading
   of what an exploit requires, not a probe of the host.
4. **The verifier checks citations, not reasoning.** It catches an invented CVE.
   It cannot catch prose that cites real CVEs but characterises them misleadingly.
5. **No EPSS**, so non-KEV findings rank only on CVSS.

---

## 10. What I'd do with another day / week

**A day**
- EPSS scores → materially better ranking of the non-KEV tail
- Internet-exposure as a scoring input (needs one CMDB field)
- ServiceNow-ready tickets grouped by *patch action*, not by CVE

**A week**
- Reconcile curated rules against authenticated scanner output (Tenable/Qualys
  already resolve CPEs) — removes my largest error source
- Persist each run and diff on `(asset_id, cve)` → makes *"how has exposure
  changed?"* answerable instead of refused
- Exception management with expiry and owner
- Attack-path context: "this workstation is one hop from the DC" should move ranking

---

## 11. Who this is for

A **vulnerability-management analyst or CTEM lead** preparing a remediation
sprint — someone who can sanity-check the rules and wants the cross-referencing
and ranking done for them.

It is **not** a self-serve CISO dashboard yet. The coverage gaps need a human
who understands what "we didn't assess Java SE" implies. The CISO summary is
built to be handed *up* by that analyst, not consumed directly.

That distinction is the product decision I'd most want to discuss.

---

## 12. If you only click three things

1. **Ask a question → "What is our highest-risk server right now and why?"**
   Shows the score decomposition and the confidence weight.
2. **How AI is used tab.** The trust argument, the actual prompts, the verifier source.
3. **Data quality & limits tab.** The Veeam/Ubuntu contradiction and the 32
   unassessed packages — what the tool admits it doesn't know.
