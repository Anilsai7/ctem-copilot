"""Optional LLM layer (Claude).

The model is given exactly two jobs, and neither of them involves producing a
security fact:

  1. PLAN     natural language -> QuerySpec (a typed, inspectable struct).
              The model chooses an intent and filters. It cannot invent a CVE,
              a CVSS score, or an asset, because the spec has no field for one.

  2. NARRATE  computed result set -> prose. The model is handed the rows the
              deterministic engine produced and asked to summarise them. It is
              explicitly forbidden from adding facts.

Then a third, non-LLM step:

  3. VERIFY   every CVE ID, asset ID, and hostname in the generated prose is
              checked against the evidence set. Anything unsupported is
              flagged on the output rather than quietly shipped.

This is the whole trust argument. An LLM that cannot reach the numbers cannot
get the numbers wrong, and a verifier that re-reads the prose catches the case
where it narrates something the data does not support.

The layer is optional by design: with no API key the deterministic router and
template renderer handle every benchmark question. The LLM improves phrasing
and handles questions the keyword router was not written for.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from . import query as Q

MODEL = "claude-opus-5"

# --- the planner's output contract ----------------------------------------
QUERYSPEC_SCHEMA = {
    "type": "object",
    "properties": {
        "intent": {"type": "string", "enum": Q.ALL_INTENTS},
        "department": {"type": ["string", "null"], "enum": Q.DEPARTMENTS + [None]},
        "asset_type": {"type": ["string", "null"],
                       "enum": ["server", "workstation", "network_device", None]},
        "criticality": {"type": ["string", "null"],
                        "enum": ["critical", "high", "medium", "low", None]},
        "product": {"type": ["string", "null"]},
        "severity": {"type": ["string", "null"],
                     "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", None]},
        "min_cvss": {"type": ["number", "null"]},
        "kev_only": {"type": "boolean"},
        "overdue_only": {"type": "boolean"},
        "stale_days": {"type": ["integer", "null"]},
        "group_by": {"type": ["string", "null"],
                     "enum": ["product", "department", "asset_type", "criticality", None]},
        "sort_by": {"type": "string", "enum": ["risk", "cvss", "due_date"]},
        "limit": {"type": "integer"},
        "interpretation": {
            "type": "string",
            "description": "One sentence restating how you understood the question, "
                           "for the analyst to sanity-check.",
        },
    },
    "required": ["intent", "kev_only", "overdue_only", "sort_by", "limit",
                 "interpretation"],
    "additionalProperties": False,
}

PLANNER_SYSTEM = """You translate a security analyst's question into a QuerySpec \
for a vulnerability exposure engine. You do not answer the question.

Available intents:
- top_risks: ranked list of findings matching filters
- top_asset: the single riskiest asset and why
- patch_priority: which software package to patch first, fleet-wide
- group_exposure: roll-up by department / asset_type / criticality
- overdue_kev: findings past their CISA remediation deadline
- posture_summary: whole-fleet executive summary
- cve_list: flat list of CVEs
- what_if_patch: counterfactual impact of patching one product
- stale_scans: assets whose last scan is older than N days
- coverage: what the system did NOT assess (blind spots)
- count: how many assets/findings match

Rules:
- Choose the single intent that best answers the question.
- Set kev_only=true only when the question is about active exploitation
  ("actively exploited", "in the wild", "KEV").
- Use severity=CRITICAL for "critical CVEs" (CVSS >= 9.0).
- For "patch X first" questions use patch_priority with group_by=product.
- For "what would patching X achieve" use what_if_patch and set product.
- If the question asks what the system missed or did not check, use coverage.
- Never invent a department or product that was not mentioned.
"""

NARRATOR_SYSTEM = """You are writing an answer for a security analyst, from a \
result set that has already been computed by a deterministic engine.

ABSOLUTE RULES:
1. Every CVE ID, asset ID, hostname, CVSS score, count, and date you write MUST
   appear in the EVIDENCE block. Do not compute, estimate, round, or infer any
   number that is not given to you.
2. If the evidence does not support a claim, do not make the claim. Say the
   data does not show it.
3. Reproduce the caveats. If findings are uncertain or coverage is incomplete,
   say so in the answer, not as a footnote.
4. Be concise and specific. An analyst needs to act on this on Monday morning.
5. Cite asset IDs and CVE IDs inline so the answer is checkable.

You are summarising, not analysing. The prioritisation logic was already
applied; explain it, do not second-guess it."""


class LlmUnavailable(RuntimeError):
    pass


def available() -> bool:
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def _client():
    try:
        import anthropic
    except ImportError as e:
        raise LlmUnavailable(
            "The 'anthropic' package is not installed. Run `pip install anthropic`, "
            "or use the deterministic mode (default)."
        ) from e
    return anthropic.Anthropic()


# ---------------------------------------------------------------------------
# 1. Planner
# ---------------------------------------------------------------------------

def plan(question: str) -> Q.QuerySpec:
    """NL -> QuerySpec using structured outputs (schema-constrained)."""
    client = _client()
    resp = client.messages.create(
        model=MODEL,
        max_tokens=2000,
        system=PLANNER_SYSTEM,
        thinking={"type": "adaptive"},
        output_config={
            "effort": "low",
            "format": {"type": "json_schema", "schema": QUERYSPEC_SCHEMA},
        },
        messages=[{"role": "user", "content": question}],
    )
    text = next(b.text for b in resp.content if b.type == "text")
    data = json.loads(text)

    spec = Q.QuerySpec(intent=data["intent"], planner="llm")
    for field in ("department", "asset_type", "criticality", "product", "severity",
                  "min_cvss", "kev_only", "overdue_only", "stale_days", "group_by",
                  "sort_by", "limit", "interpretation"):
        if data.get(field) is not None:
            setattr(spec, field, data[field])
    return spec


# ---------------------------------------------------------------------------
# 2. Narrator
# ---------------------------------------------------------------------------

def narrate(question: str, result: Dict[str, Any], deterministic_answer: str) -> str:
    """Turn a computed result set into prose, grounded in that result set."""
    client = _client()
    evidence = json.dumps(
        {
            "as_of": result["as_of"],
            "interpreted_as": result["spec"].get("interpretation"),
            "computed_facts": result["facts"],
            "matching_findings": result["matched_findings"],
            "evidence_rows": [
                {k: r[k] for k in (
                    "asset_id", "hostname", "department", "criticality", "asset_type",
                    "product", "installed_version", "cve_id", "cvss_score",
                    "cvss_severity", "in_kev", "kev_due_date", "kev_ransomware",
                    "confidence", "risk_score", "score_rationale", "caveats",
                    "last_scan_date")}
                for r in result["rows"]
            ],
            "caveats": result["caveats"],
        },
        indent=1, default=str,
    )

    resp = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        system=NARRATOR_SYSTEM,
        thinking={"type": "adaptive"},
        output_config={"effort": "medium"},
        messages=[{
            "role": "user",
            "content": (
                f"ANALYST QUESTION:\n{question}\n\n"
                f"EVIDENCE (the only facts you may use):\n{evidence}\n\n"
                f"DETERMINISTIC RENDERING (already verified correct; your prose "
                f"must not contradict it):\n{deterministic_answer}\n\n"
                f"Write the answer."
            ),
        }],
    )
    return "".join(b.text for b in resp.content if b.type == "text").strip()


# ---------------------------------------------------------------------------
# 3. Verifier  (no LLM — this is the control)
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_ASSET_RE = re.compile(r"\b[A-Z]{2,4}-(?:SRV|WS|NET|DB|APP)-\d{3}\b")


def verify_narration(text: str, result: Dict[str, Any],
                     full_index: Optional[dict] = None) -> Tuple[bool, List[str]]:
    """Check that every identifier in the prose is backed by the evidence set.

    Returns (ok, problems). This is deliberately mechanical: it cannot judge
    whether the reasoning is good, only whether the model referenced something
    it was not given. That is the failure mode that actually matters — a
    plausible-sounding CVE that does not exist in the fleet.
    """
    problems: List[str] = []

    allowed_cves = {r["cve_id"].upper() for r in result["rows"]}
    allowed_assets = {r["asset_id"] for r in result["rows"]}

    # Facts blocks legitimately name assets/CVEs that are not in `rows`
    # (e.g. patch_priority lists asset_ids per package). Accept those too.
    blob = json.dumps(result["facts"], default=str)
    allowed_cves |= {m.upper() for m in _CVE_RE.findall(blob)}
    allowed_assets |= set(_ASSET_RE.findall(blob))

    for cve in {m.upper() for m in _CVE_RE.findall(text)}:
        if cve not in allowed_cves:
            problems.append(
                f"UNSUPPORTED CVE: {cve} appears in the answer but not in the "
                f"evidence set for this query.")

    for aid in set(_ASSET_RE.findall(text)):
        if aid not in allowed_assets:
            known = (full_index and any(a["asset_id"] == aid
                                        for a in full_index.get("assets", [])))
            problems.append(
                f"UNSUPPORTED ASSET: {aid} appears in the answer but not in the "
                f"evidence set" + (" (it does exist in the inventory)." if known
                                   else " and is not in the inventory at all."))

    return (not problems), problems
