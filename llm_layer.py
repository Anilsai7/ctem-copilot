"""Optional LLM layer (Claude) — narration and question routing.

THE CENTRAL DESIGN DECISION OF THIS PROJECT LIVES HERE.

The model is given exactly two jobs, and neither of them is producing a
security fact:

  1. ROUTE     natural language -> which precomputed answer to show.
               It picks from a fixed enum. It cannot invent an intent.

  2. NARRATE   computed rows -> prose. It is handed findings that
               solve.py already computed and asked to summarise them.
               It is forbidden from adding facts.

Then a third step that is deliberately NOT an LLM:

  3. VERIFY    every CVE ID, asset ID and CVSS score in the generated prose
               is checked against the evidence set. Anything unsupported is
               flagged and the deterministic answer is shown instead.

Why this shape
--------------
The client's stated failure was a scanner producing 3,400 unprioritised
findings that the team learned to ignore. The way to make that *worse* is a
system that sounds authoritative and occasionally invents a CVE. Trust, once
lost, is not recovered by a better model.

So the LLM never touches arithmetic, version comparison, KEV lookup, or
scoring. Those are deterministic and reproducible: two analysts running the
same query get identical numbers. The LLM improves *phrasing* and *intent
understanding* — the two things it is genuinely better at than code — and a
mechanical verifier audits its output before an analyst sees it.

An LLM that cannot reach the numbers cannot get the numbers wrong.

Degradation
-----------
With no API key the whole application still works: the keyword router handles
routing and templates handle narration. The LLM is an enhancement, never a
dependency. That is deliberate — a security tool that stops working when an
external API is down is not a security tool.
"""

import json
import os
import re

MODEL = "claude-opus-5"

INTENT_KEYS = [
    "critical", "top_asset", "patch_first", "finance_kev", "overdue", "ciso",
    "unit", "apache", "network", "stale", "trend", "coverage",
]

ROUTER_SYSTEM = """You route a security analyst's question to one of a fixed set \
of precomputed answers. You do NOT answer the question.

Return only the key that best matches:
- critical     : which assets have critical / high-severity CVEs
- top_asset    : the single riskiest asset or server, and why
- patch_first  : which software package to patch first
- finance_kev  : Finance department exposure to actively exploited CVEs
- overdue      : findings past their CISA KEV remediation deadline
- ciso         : overall posture summary for an executive
- unit         : comparison across business units / departments
- apache       : impact of patching Apache HTTP Server specifically
- network      : CVEs on network devices (firewall, VPN, proxy, router)
- stale        : assets not scanned recently
- trend        : how exposure has changed over time
- coverage     : what the system did NOT assess; blind spots
- none         : the question does not match any of the above

Return the key alone, lowercase, nothing else. If genuinely unsure, return \
'none' — showing the wrong answer confidently is worse than admitting doubt."""

NARRATOR_SYSTEM = """You write an answer for a security analyst from a result set \
that a deterministic engine has already computed.

ABSOLUTE RULES:
1. Every CVE ID, asset ID, hostname, CVSS score, count and date you write MUST
   appear in the EVIDENCE block. Never compute, estimate, round or infer a
   number that was not given to you.
2. If the evidence does not support a claim, do not make it. Say the data does
   not show it.
3. Reproduce the caveats. If findings are 'likely' or 'uncertain', say so in
   the answer itself, not as a footnote.
4. Be concise and specific. An analyst has to act on this on Monday morning.
5. Cite asset IDs and CVE IDs inline so the answer is checkable.

You are summarising, not analysing. The prioritisation logic was already
applied — explain it, do not second-guess it."""


def available():
    """True if an API key and the SDK are both present."""
    if not (os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def status():
    """Human-readable reason the LLM layer is or is not active."""
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY")
                   or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    try:
        import anthropic  # noqa: F401
        has_sdk = True
    except ImportError:
        has_sdk = False
    if has_key and has_sdk:
        return True, "Claude narration active"
    if not has_sdk:
        return False, "anthropic SDK not installed (`pip install anthropic`)"
    return False, "ANTHROPIC_API_KEY not set"


def _client():
    import anthropic
    return anthropic.Anthropic()


def friendly_error(exc):
    """Translate an API exception into (headline, detail) for the UI.

    Raw provider exceptions leak request IDs and stack detail at the analyst,
    which reads as a crash. Every one of these is a *designed* fallback: the
    deterministic answer is still correct and still shown. The wording says so.
    """
    s = str(exc).lower()
    if "credit balance" in s or "billing" in s or "quota" in s:
        return ("Claude narration unavailable — the API account has no credits.",
                "This is the designed fallback, not a failure. The deterministic "
                "answer below is the same one the tool produces with no LLM "
                "configured at all. Add credits at console.anthropic.com "
                "(Plans & Billing) to enable narration.")
    if "authentication" in s or "invalid x-api-key" in s or "401" in s:
        return ("Claude narration unavailable — the API key was rejected.",
                "Check ANTHROPIC_API_KEY for a typo or a truncated paste. The "
                "deterministic answer below is unaffected.")
    if "rate limit" in s or "429" in s:
        return ("Claude narration unavailable — API rate limit reached.",
                "Retry in a moment. The deterministic answer below is unaffected.")
    if "overloaded" in s or "529" in s:
        return ("Claude narration unavailable — the API is temporarily overloaded.",
                "Retry in a moment. The deterministic answer below is unaffected.")
    if "connection" in s or "timeout" in s or "network" in s:
        return ("Claude narration unavailable — could not reach the API.",
                "Check network access. The deterministic answer below is "
                "unaffected — the tool does not depend on an external API.")
    return ("Claude narration unavailable.",
            f"The deterministic answer below is unaffected. Detail: "
            f"{str(exc)[:180]}")


# ---------------------------------------------------------------------------
# 1. Route
# ---------------------------------------------------------------------------
def route(question):
    """NL -> intent key. Returns None when the model is unsure."""
    resp = _client().messages.create(
        model=MODEL,
        max_tokens=1500,
        system=ROUTER_SYSTEM,
        thinking={"type": "adaptive"},
        output_config={"effort": "low"},
        messages=[{"role": "user", "content": question}],
    )
    txt = "".join(b.text for b in resp.content if b.type == "text").strip().lower()
    key = re.sub(r"[^a-z_]", "", txt)
    return key if key in INTENT_KEYS else None


# ---------------------------------------------------------------------------
# 2. Narrate
# ---------------------------------------------------------------------------
def narrate(question, findings, extra_facts=None):
    """Turn computed findings into prose grounded in those findings only."""
    evidence = {
        "computed_facts": extra_facts or {},
        "findings": [{
            "asset_id": f["asset_id"], "hostname": f["hostname"],
            "department": f["department"], "criticality": f["criticality"],
            "asset_type": f["asset_type"], "product": f["product"],
            "version": f["version"], "cve": f["cve"], "cvss": f["cvss"],
            "in_kev": f["in_kev"], "cisa_due": f["due"], "overdue": f["overdue"],
            "ransomware": f["ransomware"], "confidence": f["confidence"],
            "caveat": f["caveat"], "risk_score": f["risk"],
            "why": f["why"],
        } for f in findings],
    }
    resp = _client().messages.create(
        model=MODEL,
        max_tokens=3000,
        system=NARRATOR_SYSTEM,
        thinking={"type": "adaptive"},
        output_config={"effort": "medium"},
        messages=[{"role": "user", "content":
                   f"ANALYST QUESTION:\n{question}\n\n"
                   f"EVIDENCE (the only facts you may use):\n"
                   f"{json.dumps(evidence, indent=1, default=str)}\n\n"
                   f"Write the answer."}],
    )
    return "".join(b.text for b in resp.content if b.type == "text").strip()


# ---------------------------------------------------------------------------
# 3. Verify  (no LLM — this is the control)
# ---------------------------------------------------------------------------
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_ASSET_RE = re.compile(r"\b[A-Z]{2,4}-(?:SRV|WS|NET)-\d{3}\b")
_CVSS_RE = re.compile(r"CVSS\s*([0-9]{1,2}(?:\.[0-9])?)", re.I)


def verify(text, findings):
    """Audit generated prose against the evidence set.

    Mechanical on purpose. It cannot judge whether the reasoning is good, only
    whether the model referenced something it was never given — which is the
    failure mode that actually destroys trust: a plausible CVE that is not in
    the fleet.

    Returns (ok, problems).
    """
    problems = []
    ok_cves = {f["cve"].upper() for f in findings}
    ok_assets = {f["asset_id"] for f in findings}
    ok_cvss = {str(f["cvss"]) for f in findings}

    for c in {m.upper() for m in _CVE_RE.findall(text)}:
        if c not in ok_cves:
            problems.append(f"UNSUPPORTED CVE: {c} is not in the evidence set.")

    for a in set(_ASSET_RE.findall(text)):
        if a not in ok_assets:
            problems.append(f"UNSUPPORTED ASSET: {a} is not in the evidence set.")

    for s in set(_CVSS_RE.findall(text)):
        if s not in ok_cvss:
            problems.append(
                f"UNSUPPORTED CVSS: {s} does not match any score in the evidence "
                f"set (present: {sorted(ok_cvss)}).")

    return (not problems), problems
