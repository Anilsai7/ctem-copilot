"""Risk scoring.

Deliberately a transparent additive model rather than anything learned or
LLM-generated. Three reasons:

  1. Reproducible. The same inputs always produce the same number, so a
     finding cannot silently change rank between two runs of the report.
  2. Auditable. Every point is attributable to a named component, so the
     answer to "why is this number 1" is a sentence, not a shrug.
  3. Arguable. A client can disagree with the weights and change them. That
     is a feature: prioritisation is a business decision, and the tool should
     make the policy explicit instead of burying it.

    Component            Max   Rationale
    -------------------  ----  --------------------------------------------
    CVSS severity         30   Technical severity, but capped -- CVSS alone
                               is what produced the unusable 3,400-item list.
    Exploitation (KEV)    30   Whether attackers are actually using it. This
                               is weighted equal to severity on purpose: a
                               7.5 under active exploitation outranks a
                               theoretical 9.8.
    Asset criticality     25   Business impact of the host.
    Remediation urgency   15   CISA due date proximity / overdue status.

Total 0-100. Confidence is applied as a ranking weight and reported
separately, so an uncertain finding is never presented as fact.

KNOWN GAP: network exposure (internet-facing vs internal) is one of the
strongest real prioritisation signals and is absent from the inventory, so it
contributes nothing here. Any production version would need it.
"""

from datetime import date, datetime
from typing import Dict, List, Optional

from .match import CONFIRMED, LIKELY, UNCERTAIN, Finding

CRITICALITY_POINTS = {"critical": 25.0, "high": 18.0, "medium": 10.0, "low": 4.0}

CONFIDENCE_WEIGHT = {CONFIRMED: 1.0, LIKELY: 0.90, UNCERTAIN: 0.75}

MAX_SEVERITY = 30.0
MAX_EXPLOIT = 30.0
MAX_URGENCY = 15.0


def _parse_date(s: Optional[str]) -> Optional[date]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def score_finding(f: Finding, as_of: date) -> Finding:
    b: Dict[str, float] = {}
    why: List[str] = []

    # --- severity ---------------------------------------------------------
    if f.cvss_score is not None:
        b["severity"] = round(f.cvss_score / 10.0 * MAX_SEVERITY, 2)
        why.append(
            f"CVSS {f.cvss_score} ({f.cvss_severity}) contributes "
            f"{b['severity']:.1f}/{MAX_SEVERITY:.0f}.")
    else:
        # No score is not the same as a low score. Assume mid-range and say so.
        b["severity"] = 15.0
        why.append(
            "No CVSS base score published; assumed mid-range "
            f"({b['severity']:.1f}/{MAX_SEVERITY:.0f}) rather than zero, "
            "to avoid under-ranking an unscored CVE.")

    # --- exploitation -----------------------------------------------------
    if f.in_kev:
        pts = 25.0
        note = (f"Listed in CISA KEV (added {f.kev_date_added}) — confirmed "
                f"exploitation in the wild: +25.")
        if (f.kev_ransomware or "").lower() == "known":
            pts += 5.0
            note += " Known use in ransomware campaigns: +5."
        b["exploitation"] = pts
        why.append(note)
    else:
        b["exploitation"] = 0.0
        why.append("Not in CISA KEV — no confirmed in-the-wild exploitation: +0.")

    # --- asset criticality ------------------------------------------------
    pts = CRITICALITY_POINTS.get((f.criticality or "").lower(), 10.0)
    b["asset_criticality"] = pts
    why.append(f"Asset criticality '{f.criticality}' on {f.asset_id}: +{pts:.0f}.")

    # --- remediation urgency ---------------------------------------------
    due = _parse_date(f.kev_due_date)
    if due:
        days = (due - as_of).days
        if days < 0:
            b["urgency"] = 15.0
            why.append(
                f"CISA remediation due {f.kev_due_date} — OVERDUE by "
                f"{abs(days)} days: +15.")
        elif days <= 14:
            b["urgency"] = 11.0
            why.append(f"CISA due {f.kev_due_date} — {days} days remaining: +11.")
        elif days <= 30:
            b["urgency"] = 7.0
            why.append(f"CISA due {f.kev_due_date} — {days} days remaining: +7.")
        else:
            b["urgency"] = 4.0
            why.append(f"CISA due {f.kev_due_date} — {days} days remaining: +4.")
    else:
        b["urgency"] = 0.0
        why.append("No CISA due date (not a KEV entry): +0.")

    raw = round(sum(b.values()), 2)
    weight = CONFIDENCE_WEIGHT.get(f.confidence, 0.75)
    if weight < 1.0:
        why.append(
            f"Confidence '{f.confidence}' applies a x{weight} ranking weight "
            f"({raw:.1f} -> {round(raw * weight, 1)}).")

    f.score_breakdown = b
    f.risk_score = raw
    f.score_rationale = why
    f.ranked_score = round(raw * weight, 2)
    return f


def score_all(findings: List[Finding], as_of: Optional[date] = None) -> List[Finding]:
    as_of = as_of or date.today()
    for f in findings:
        score_finding(f, as_of)
    return sorted(findings, key=lambda x: (-x.ranked_score, x.asset_id, x.cve_id))


def score_action(a: Dict, as_of: date) -> Dict:
    """Score a remediation action — the unit the patching team actually works.

    Why this exists
    ---------------
    Scoring individual CVEs reproduces the client's original problem. Chrome
    114 in 2026 is legitimately behind ~2 years of releases, so NVD correctly
    reports thousands of applicable CVEs for it. Ranked as CVEs, one stale
    browser drowns an actively-exploited Fortinet appliance.

    But nobody remediates a CVE. They upgrade Chrome on a host — one ticket,
    one change window, one reboot — and that single action closes all of them.
    So the ranked unit is (asset, product), and CVE count becomes an attribute
    of the action rather than the thing being counted.

    Deliberately NOT scored: CVE volume. Counting it would let a package with
    many low-severity issues outrank one under active exploitation, which is
    the exact failure we are correcting. Volume is reported as context.
    """
    b: Dict[str, float] = {}
    why: List[str] = []

    if a["max_cvss"] is not None:
        b["severity"] = round(a["max_cvss"] / 10.0 * MAX_SEVERITY, 2)
        why.append(
            f"Worst CVE on this package is {a['max_cvss_cve']} at CVSS "
            f"{a['max_cvss']}: {b['severity']:.1f}/{MAX_SEVERITY:.0f}.")
    else:
        b["severity"] = 15.0
        why.append("No CVSS score available; assumed mid-range rather than zero.")

    if a["kev_cve_count"]:
        pts = 25.0
        note = (f"{a['kev_cve_count']} of its {a['cve_count']} CVEs are on CISA KEV "
                f"— confirmed exploitation in the wild: +25.")
        if a["ransomware"]:
            pts += 5.0
            note += " At least one is linked to ransomware campaigns: +5."
        b["exploitation"] = pts
        why.append(note)
    else:
        b["exploitation"] = 0.0
        why.append("No CVE on this package is in CISA KEV: +0.")

    pts = CRITICALITY_POINTS.get((a["criticality"] or "").lower(), 10.0)
    b["asset_criticality"] = pts
    why.append(f"Asset criticality '{a['criticality']}' on {a['asset_id']}: +{pts:.0f}.")

    due = _parse_date(a["earliest_due"])
    if due:
        days = (due - as_of).days
        if days < 0:
            b["urgency"] = 15.0
            why.append(f"Earliest CISA deadline {a['earliest_due']} — OVERDUE by "
                       f"{abs(days)} days: +15.")
        elif days <= 14:
            b["urgency"] = 11.0
            why.append(f"Earliest CISA deadline {a['earliest_due']} — {days} days left: +11.")
        elif days <= 30:
            b["urgency"] = 7.0
            why.append(f"Earliest CISA deadline {a['earliest_due']} — {days} days left: +7.")
        else:
            b["urgency"] = 4.0
            why.append(f"Earliest CISA deadline {a['earliest_due']} — {days} days left: +4.")
    else:
        b["urgency"] = 0.0
        why.append("No CISA deadline applies: +0.")

    a["risk_score"] = round(sum(b.values()), 2)
    a["score_breakdown"] = b
    a["score_rationale"] = why
    a["band"] = band(a["risk_score"])
    return a


def band(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def scan_age_days(f: Finding, as_of: date) -> Optional[int]:
    d = _parse_date(f.last_scan_date)
    return None if d is None else (as_of - d).days
