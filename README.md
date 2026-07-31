# CTEM Exposure Copilot

Ask natural-language questions about a fleet's vulnerability exposure and get a
grounded, cited, prioritised answer.

Built against the provided synthetic inventory (23 assets, 6 business units)
cross-referenced with the **live CISA KEV catalog**.

```bash
pip install -r requirements.txt
streamlit run app.py          # web UI  -> http://localhost:8501
python solve.py               # CLI report, all 11 questions
```

Core engine (`solve.py`) is **standard library only**. Streamlit and pandas are
needed for the UI, nothing else.

### Optional — enable Claude narration

The app answers all 12 questions without it. To see the LLM layer and its
verifier in action:

```bash
export ANTHROPIC_API_KEY=sk-ant-...     # Windows Git Bash / macOS / Linux
python -m streamlit run app.py
```

The sidebar then shows 🟢 *Claude narration active*. Toggle **Use Claude to
write answers**; every generated answer is audited by a non-LLM verifier before
it is displayed.

Deploying to Streamlit Cloud: add the key under **Settings → Secrets** as
`ANTHROPIC_API_KEY = "sk-ant-..."` rather than an environment variable.

Not working? Run `python check_ai.py` — it tests each precondition in turn
(interpreter, SDK, key, live API call) and names the one that failed.

---

## The problem

The client's scanner produced 3,400 findings and the security team started
ignoring it. That is not a data problem — the data was correct. It is a
**prioritisation and trust** problem:

1. No ranking, so there was no answer to "what do we do Monday morning".
2. No business context, so a critical CVE on a test box outranked a real one.
3. No explanation, so nobody could tell which findings deserved the panic.

Adding an LLM to that pipeline can easily make it worse: a system that *sounds*
authoritative and occasionally invents a CVE is more dangerous than a
spreadsheet nobody reads. So the design starts from the trust question.

---

## Architecture

```
  assets.json ──┐
                ├──► match (explicit version rules) ──► score ──► answer
  CISA KEV ─────┘         │                              │          │
   (live)                 │                              │          │
                          ▼                              ▼          ▼
                    confidence tier              confidence     citations
                 confirmed/likely/uncertain        weighting     + caveats

  question ──► ROUTE ──► [ engine above ] ──► NARRATE ──► VERIFY ──► answer
               LLM or                          LLM or       never
               keywords                        templates    an LLM
```

**The LLM never produces a security fact.** It routes questions and writes prose
over rows the engine already computed. Matching, scoring, KEV lookup and date
arithmetic are deterministic — two analysts running the same query get identical
numbers.

| Stage | Who | Why |
|---|---|---|
| Version → CVE applicability | Python, NVD-sourced ranges | Reproducible, checkable |
| Exploitation, due dates, ransomware | Live CISA KEV feed | Authoritative, current |
| Risk scoring | Transparent additive formula | Arguable — a client can change the weights |
| **Question → intent** | **Claude** or keyword router | Genuinely ambiguous |
| **Rows → prose** | **Claude** or templates | Genuinely a language task |
| **Citation audit** | **Regex, no LLM** | A model cannot audit itself |

*An LLM that cannot reach the numbers cannot get the numbers wrong.*

Every generated answer is scanned for CVE IDs, asset IDs and CVSS scores; each is
checked against the evidence rows. Unsupported reference → the answer is rejected
and the deterministic one shown. See the **How AI is used** tab, or
`llm_layer.py`.

**Runs fully without an API key** — keyword routing and templates handle all 12
questions. The LLM is an enhancement, never a dependency.

---

## Scope decisions (the important part)

**Why not query all of NVD by CPE.** I built that first. Querying NVD by
`virtualMatchString` for every installed package returned **14,080 findings** —
Chrome 114 alone matched **2,279 CVEs**, because every CVE fixed in any *later*
release genuinely applies. Technically correct, and it reproduced the client's
3,400-finding problem four times over. I cut it.

That abandoned pipeline is still in `vulnintel/` + `build_index.py` as evidence
of the experiment and why it was rejected.

**But precision must not become blindness.** Browsers get one high-signal KEV
CVE (`CVE-2023-4863`, libwebp), not their whole history — because it lands on
the CEO and CISO laptops and is overdue.

**Operating systems are excluded.** Pulling every Windows/RHEL CVE recreates the
noise problem, and OS patching runs on a separate Patch-Tuesday → WSUS/MECM
workflow with different owners.

**Analysis is anchored to the newest scan date (2026-06-06), not wall-clock.**
Using today's date makes "days overdue" drift on every run. Anchoring to the
data's own most recent observation makes the report reproducible.

---

## Confidence tiers

Version applicability and exploitability are not the same claim:

| Tier | Meaning | Weight |
|---|---|---:|
| `confirmed` | Version is in the affected range; nothing else is required | ×1.00 |
| `likely` | Version affected, but exploitation needs config the inventory doesn't record | ×0.85 |
| `uncertain` | A load-bearing precondition is unproven, or the inventory contradicts itself | ×0.70 |

Uncertain findings are **surfaced and labelled, never dropped**. Cisco IOS XE is
CVSS 10.0 but scores 66/100, because the Web UI precondition is unproven.

---

## Risk scoring

| Component | Max | Rationale |
|---|---:|---|
| CVSS severity | 30 | Capped — CVSS alone produced the unusable 3,400-item list |
| Exploitation (CISA KEV) | 30 | Equal to severity: a 7.5 under active attack beats a theoretical 9.8 |
| Asset criticality | 25 | Business impact of the host |
| Deadline urgency | 15 | CISA due-date proximity / overdue |

Subtotal × confidence weight. Every finding carries its own `score_rationale`.

**Known gap:** network exposure (internet-facing vs internal) is one of the
strongest real prioritisation signals and is **absent from the inventory**, so it
contributes nothing. The tool does not invent it.

---

## Data-quality checks

Run against the inventory *before* any finding is trusted:

- **7 assets have `last_scan_date` after `metadata.generated_date`** — scans
  dated after the export was generated.
- **`IT-SRV-003` reports Ubuntu 18.04 but lists Veeam Backup & Replication**,
  which is Windows-only server software. Findings for it are auto-downgraded to
  `uncertain`.
- **The brief describes 25 assets; the file contains 23.**
- Scan dates span 2026-01-15 → 2026-06-06.

---

## Handling ambiguity honestly

The system distinguishes *"we checked and you're clean"* from *"we did not
check"* — conflating those is how vulnerability programmes lose credibility.

- 32 of 47 inventory packages have **no detection rule** and are reported as
  coverage gaps, never as zero findings. Ask *"what did you not assess?"*
- **Java SE** findings are `uncertain` on purpose: NVD's CPE is
  `oracle:jre:1.8.0` with no update granularity, so per-update applicability
  cannot be machine-verified. The match relies on Oracle's CPU advisory and says
  so.
- *"How has our exposure changed since last month?"* returns an explicit
  **refusal** — one snapshot cannot support a trend, and inventing one would be
  fabrication.

---

## Where this can still fail

1. **Version rules are hand-curated** — a wrong rule produces a confidently
   wrong finding. Every range in `RULES` was read from NVD CPE nodes, but the
   table is the largest systematic risk.
2. **Inventory accuracy is assumed** — if the CMDB says 2.4.49 and the host runs
   2.4.58, every downstream conclusion is wrong. Production needs authenticated
   scan data.
3. **Confidence tiers encode judgement, not measurement** — `likely` reflects our
   reading of what an exploit requires, not a probe of the host.
4. **No EPSS** — exploit-prediction scoring would improve ranking of non-KEV findings.
5. **No attack-path context** — "this workstation is one hop from the DC" doesn't
   affect ranking yet.

---

## What I'd do next

**A day:** EPSS scores; internet-exposure as a scoring input; ServiceNow-ready
change tickets grouped by patch action rather than by CVE.

**A week:** reconcile the curated rules against authenticated scanner output
(Tenable/Qualys already resolve CPEs); exception management with expiry and
owner; persist each run so the trend question becomes answerable; attack-path
reasoning.

---

## Who this is for

A **vulnerability-management analyst or CTEM lead** preparing a remediation
sprint — someone who can sanity-check the rules and wants the cross-referencing
and ranking done for them.

It is *not* yet a self-serve CISO dashboard: the coverage gaps need a human who
understands what "we didn't assess Java SE" implies. The CISO-facing summary is
designed to be handed *up* by that analyst.

---

## Files

```
WALKTHROUGH.md        deliverable 2 — decisions, shortcuts, what I would improve
DISCUSSION.md         deliverable 3 — trust, agentic design, product thinking
llm_layer.py          optional Claude narration + non-LLM citation verifier
solve.py              detection rules, scoring, free-text router, CLI report
app.py                Streamlit UI (4 tabs)
requirements.txt      streamlit, pandas
EXPOSURE_REPORT.txt   generated CLI output — all 11 questions
data/assets.json      provided synthetic inventory
cache/kev.json        CISA KEV snapshot (offline fallback; live feed preferred)

vulnintel/            ABANDONED full-NVD pipeline — kept as evidence of the
build_index.py        14,080-finding experiment and why it was cut
ask.py
```
