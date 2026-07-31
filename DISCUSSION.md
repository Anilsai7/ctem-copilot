# Discussion

*Deliverable 3 — trust & hallucination, agentic workflow design, product thinking.*

---

## 1. Trust & hallucination

### Why security teams distrust AI-generated risk answers

Because the failure mode is invisible. A scanner that misses a CVE fails
loudly — you find out at the post-incident review. A language model that
*invents* `CVE-2023-48291` fails silently: it looks exactly like a real finding,
it has the right shape, and it survives right up until an analyst tries to patch
something that doesn't exist. Then the analyst stops trusting **every** finding
the tool produces, including the correct ones.

The client in this brief already lived the non-AI version: 3,400 findings, no
prioritisation, and a team that learned to ignore the tool. **Trust, once lost,
is not recovered by a better model.** So the design question isn't "how do I make
the LLM more accurate", it's "how do I make it structurally incapable of the
error that destroys trust".

### How this approach reduces the risk

**1. The LLM cannot reach the numbers.** Matching, version comparison, KEV
lookup, date arithmetic and scoring are all deterministic Python. The model is
handed rows that already exist and asked to summarise them. It has no path to
compute or look up a fact.

**2. Reproducibility.** The same query always returns the same numbers. Two
analysts comparing notes see identical output. That is a precondition for a CISO
signing off on a sprint, and it is impossible if generation sits in the data path.

**3. A non-LLM verifier audits every generated answer.** `llm_layer.verify()`
extracts every CVE ID, asset ID and CVSS score from the prose and checks each
against the evidence rows. Unsupported reference → the answer is **rejected**,
the deterministic answer is shown, and the rejected text stays visible for
inspection.

Tested with a deliberately fabricated sentence, it caught all three inventions —
bad CVE, bad asset, bad CVSS.

**4. Confidence tiers stop overclaiming.** `confirmed` / `likely` / `uncertain`
separate "the version is affected" from "this is exploitable here". Cisco IOS XE
is CVSS 10.0 but scores 66/100 because the Web UI precondition is unproven.

**5. Absence of data is reported as absence of data.** 32 of 47 packages have no
detection rule; they are listed as coverage gaps, never as clean. Conflating "we
checked and you're fine" with "we didn't check" is its own kind of lie.

**6. The system refuses.** *"How has exposure changed since last month?"* returns
an explicit refusal — one snapshot cannot support a trend, and inventing one
would be fabrication.

### Where it can still fail — honestly

1. **The verifier checks citations, not reasoning.** It catches an invented CVE
   ID. It **cannot** catch prose that cites real CVEs but characterises them
   misleadingly — "this is trivially exploitable" when it isn't. That's the
   residual hallucination surface and I don't have a mechanical answer for it.
2. **Curated rules are a single point of systematic error.** Every range was read
   from NVD CPE data, but a wrong rule produces a *confidently wrong* finding
   that no verifier catches, because it's internally consistent.
3. **Garbage in.** If the CMDB says 2.4.49 and the host runs 2.4.58, every
   conclusion is wrong and everything still looks right.
4. **Confidence tiers are judgement, not measurement.** `likely` reflects my
   reading of exploit prerequisites, not a probe of the host.
5. **Routing can misfire.** A misrouted question shows the wrong-but-true
   answer. Mitigated by displaying the interpretation ("Interpreted as: …") so
   the user can see the misread — but a distracted analyst may not notice.

**The honest summary:** this design eliminates *fabricated identifiers*, which is
the failure mode that destroys trust fastest. It does not eliminate *wrong
analysis*, and I would not claim otherwise.

---

## 2. Agentic workflow design

### The structure

```
question ──► ROUTE ──► [ deterministic engine ] ──► NARRATE ──► VERIFY ──► answer
             LLM or      ingest · match · score      LLM or      never
             keywords    KEV join · confidence       templates   an LLM
```

Five stages, with a hard boundary: **stages that produce facts contain no
generation; stages that contain generation produce no facts.**

### Why this structure and not others

**Why not a single LLM call over the raw data?** Three reasons. It cannot
reliably compare `1.0.2u` against `1.0.2za` (OpenSSL letter ordering) or
`13.5` against `13.7`. It cannot be audited — there's no intermediate to check.
And it isn't reproducible, which kills it for compliance-adjacent work.

**Why not a fully autonomous tool-calling agent?** I considered it and rejected
it for this use case. An agent that decides *which* feeds to query and *how* to
correlate is more flexible but non-deterministic: the same question can take
different paths and produce different numbers. For an exploratory research task
that's a feature; for a remediation queue a CISO signs off on, it's a defect.
The structured pipeline trades flexibility for auditability, and here that's the
right trade.

**Why a typed intermediate representation?** The router emits an intent key from
a fixed enum, not free text. It cannot invent an intent, and the interpretation
is displayed so a user can see a misread. In the larger NVD version
(`vulnintel/query.py`) this is a full `QuerySpec` dataclass — intent, filters,
grouping, sort — that an analyst can inspect and challenge.

**Why keep a non-LLM path?** Because a security tool that stops working when an
external API is down is not a security tool. Everything works with no API key.
It also makes the LLM's contribution measurable: you can A/B the same question
with the toggle on and off.

### The verification pass

Two independent methods, and disagreement is surfaced rather than resolved:

- In the **NVD version**, every CVE that NVD returns as applicable is *re-checked
  locally* against the raw CPE ranges. Agreement → `confirmed`. Local check
  inconclusive → `likely`. Contradiction → `uncertain`, flagged as a conflict.
- In the **shipped version**, the generated prose is re-checked against the
  evidence set.

The point isn't that my checker beats NVD's. It's that when two methods disagree,
an analyst should see the disagreement instead of a single confident number.

### What I'd change with more time

Add a **critic pass**: a second model call that reads the answer *and* the
evidence and flags overclaiming — the gap the regex verifier can't cover. I'd
run it as an advisory flag, not a gate, until I trusted its precision.

---

## 3. Product thinking

### Who this is for **today**

A **vulnerability-management analyst or CTEM lead** preparing a remediation
sprint. Concretely: someone who owns the patching queue, has to justify sequence
to service owners, and currently spends 2–3 hours cross-referencing.

They are the right user because they can do the one thing the tool needs from a
human — **sanity-check a finding**. When it says Cisco IOS XE is `uncertain`
pending Web UI exposure, that analyst knows how to check in five minutes. They
get the 2–3 hours back and keep the judgement.

### Who it is **not** for yet

**A CISO self-serving answers.** The tool produces a CISO summary, but it's
designed to be handed *up* by the analyst, not consumed directly. The reason is
the coverage gaps: 32 unassessed packages and OS patching out of scope. Those
need someone who understands what "we didn't assess Java SE" implies. A CISO
reading "39 findings" without that context would under-estimate exposure — and
the tool would have caused the error while looking helpful.

**A fully automated remediation pipeline.** Confidence tiers are judgement, not
measurement. Auto-ticketing an `uncertain` finding wastes a change window;
auto-ticketing at scale wastes the team's trust.

### What would make it CISO-ready

1. **Coverage above ~90%** of the estate, so the floor is close to the ceiling.
   That means reconciling against authenticated scanner output rather than a
   curated rule table.
2. **Trend data.** The first question every CISO asks is "are we getting better?"
   Right now the tool refuses — correctly, but a refusal is not an answer.
3. **Internet-exposure data**, the single biggest missing prioritisation input.

### The product insight I'd lead with

**The unit of work is not a CVE — it's a remediation action.**

Nobody remediates a CVE. They upgrade a package on a host: one ticket, one
change window, one reboot. That single action might close 2 CVEs or 2,279.

This is exactly why the full-NVD version failed. It counted 14,080 asset-CVE
pairs — a true number that answers no question anyone asks. Ranked as CVEs, one
stale browser buries an actively-exploited firewall.

Getting the unit right is what turns a list into a plan. It's also why "which
package should we patch first?" shows **two rankings** — *most total exposure
removed* and *worst single item* — because those genuinely answer different
questions, and pretending one number covers both is how you lose the analyst
who notices.

### The metric I'd hold it to

Not findings surfaced. **Time-to-first-patch on KEV-listed, overdue findings on
business-critical assets** — and whether the security team still opens the tool
in month three.

The previous tool failed that test at 3,400 findings. Mine has to survive it at 39.
