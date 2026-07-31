"""Deterministic answer rendering.

Turns an executor result into analyst-facing text. No language model is
involved: these are templates over computed facts, so the numbers in the prose
are the numbers in the result set by construction.

Two citation formats, because there are two units:

  ACTION  what the patching team does — "upgrade Chrome on EXEC-WS-002".
          One ticket, one change window. This is what gets ranked.
  FINDING the CVE-level evidence behind an action, for the sceptical analyst
          who wants to verify the claim.

Every line carries asset ID, product+version, CVE ID, CVSS (with the metric
version and source), KEV status, CISA due date, and confidence.
"""

from datetime import date, datetime
from typing import Any, Dict, List, Optional

from . import query as Q


def _d(s: Optional[str]):
    if not s:
        return None
    try:
        return datetime.strptime(s[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def _due_phrase(due_str: Optional[str], as_of: Optional[date]) -> str:
    d = _d(due_str)
    if not d:
        return ""
    if as_of:
        delta = (d - as_of).days
        return (f"CISA due {due_str} (OVERDUE by {abs(delta)}d)" if delta < 0
                else f"CISA due {due_str} ({delta}d left)")
    return f"CISA due {due_str}"


def cite_action(a: dict, as_of: Optional[date] = None) -> str:
    """One-line citation for a remediation action."""
    kev = (f"{a['kev_cve_count']} on KEV" if a["kev_cve_count"] else "none on KEV")
    due = _due_phrase(a.get("earliest_due"), as_of)
    bits = [
        f"[{a['asset_id']} | {a['hostname']}]",
        f"{a['product']} {a['installed_version']}",
        f"— {a['cve_count']} applicable CVEs ({kev})",
        f"— worst {a['max_cvss_cve']} CVSS {a['max_cvss']}",
    ]
    if due:
        bits.append(f"— {due}")
    if a.get("ransomware"):
        bits.append("— ransomware-linked")
    bits.append(f"— risk {a['risk_score']:.0f}/100 [{a['band']}]")
    return " ".join(bits)


def cite(f: dict, as_of: Optional[date] = None) -> str:
    """One-line citation for a single finding (CVE-level evidence)."""
    score = "no CVSS" if f["cvss_score"] is None else f"CVSS {f['cvss_score']}"
    metric = f" {f['cvss_metric']}".rstrip() if f.get("cvss_metric") else ""
    src = f.get("cvss_source") or "n/a"
    kev = "not in KEV"
    if f["in_kev"]:
        kev = f"KEV added {f['kev_date_added']}"
        due = _due_phrase(f.get("kev_due_date"), as_of)
        if due:
            kev += f", {due}"
        if (f.get("kev_ransomware") or "").lower() == "known":
            kev += ", ransomware-linked"
    return (f"[{f['asset_id']}] {f['product']} {f['installed_version']} — "
            f"{f['cve_id']} — {score}{metric} (src: NVD/{src}) — {kev} — "
            f"confidence {f['confidence']}")


def _actions_block(actions: List[dict], as_of: date, header: str,
                   limit: int = 10) -> List[str]:
    if not actions:
        return []
    out = [f"{header}:"]
    for i, a in enumerate(actions[:limit], 1):
        out.append(f"  {i:>2}. " + cite_action(a, as_of))
    if len(actions) > limit:
        out.append(f"      ... and {len(actions) - limit} more.")
    return out


def _evidence_block(rows: List[dict], as_of: date,
                    header: str = "CVE-LEVEL EVIDENCE") -> List[str]:
    if not rows:
        return []
    out = [f"{header}:"]
    for f in rows:
        out.append("  - " + cite(f, as_of))
        for c in f.get("caveats", []):
            out.append(f"      ! {c}")
    return out


def render(result: Dict[str, Any]) -> str:
    spec = result["spec"]
    as_of = _d(result["as_of"]) or date.today()
    facts = result["facts"]
    rows = result["rows"]
    actions = result.get("actions", [])
    intent = spec["intent"]
    L: List[str] = []

    if intent == Q.POSTURE_SUMMARY:
        L += _posture(facts, actions, as_of)
    elif intent == Q.PATCH_PRIORITY:
        L += _patch(facts, actions, as_of)
    elif intent == Q.GROUP_EXPOSURE:
        L += _group(facts, spec, actions, as_of)
    elif intent == Q.TOP_ASSET:
        L += _top_asset(facts, actions, rows, as_of)
    elif intent == Q.WHAT_IF_PATCH:
        L += _what_if(facts, actions, as_of)
    elif intent == Q.STALE_SCANS:
        L += _stale(facts)
    elif intent == Q.COVERAGE:
        L += _coverage(facts)
    elif intent == Q.COUNT:
        L += _count(facts, spec, actions, as_of)
    elif intent in (Q.CVE_LIST, Q.OVERDUE_KEV):
        L += _cve_level(facts, spec, rows, as_of)
    else:
        L += _generic(facts, actions, as_of)

    if result.get("caveats"):
        L += ["", "CAVEATS:"]
        L += [f"  ! {c}" for c in result["caveats"]]
    return "\n".join(L)


# --- per-intent renderers -------------------------------------------------

def _posture(f, actions, as_of) -> List[str]:
    worst = f["worst_actions"][0] if f["worst_actions"] else None
    worst_s = (f"{worst['product']} on {worst['asset_id']}" if worst else "n/a")
    s1 = (f"Across {f['total_assets']} assets we identified {f['remediation_actions']} "
          f"distinct remediation actions — {f['assets_with_findings']} hosts running "
          f"software with known vulnerabilities — drawn from {f['distinct_cves']} "
          f"applicable CVEs.")
    s2 = (f"{f['kev_actions']} of those actions involve at least one CVE that CISA "
          f"confirms is being exploited in the wild ({f['kev_distinct_cves']} such "
          f"CVEs across {f['kev_assets']} hosts), {f['overdue_actions']} are already "
          f"past their federal remediation deadline, and the single worst item is "
          f"{worst_s}.")
    s3 = (f"This is a floor, not a ceiling: {f['unassessed_software_instances']} "
          f"software instances could not be assessed at all, and operating-system "
          f"patching is out of scope for this analysis.")
    return ["CISO SUMMARY (3 sentences):", "",
            f"  1. {s1}", f"  2. {s2}", f"  3. {s3}", "",
            f"  Scale note: those {f['remediation_actions']} actions sit on top of "
            f"{f['underlying_findings']} raw asset-CVE pairs. We rank the actions, "
            f"not the pairs — a fleet-wide CVE count is a number, not a plan.", ""] + \
        _actions_block(actions, as_of, "TOP REMEDIATION ACTIONS", 5)


def _patch(f, actions, as_of) -> List[str]:
    pkgs = f.get("packages", [])
    if not pkgs:
        return ["No packages matched the filters."]
    top = pkgs[0]
    L = ["PATCH PRIORITY — ranked by the worst single remediation action each "
         "package causes.", "",
         f"  #1  {top['product']}  (deployed: {', '.join(top['versions'])})",
         f"      Affects {top['assets_affected']} host(s): {', '.join(top['asset_ids'])}",
         f"      Worst action scores {top['worst_action_score']:.0f}/100; "
         f"max CVSS {top['max_cvss']}; closes {top['cve_count']} applicable CVEs.",
         f"      {top['critical_assets']} business-critical host(s) affected."]
    if top["kev_cves"]:
        shown = ", ".join(top["kev_cves"][:6])
        more = f" (+{len(top['kev_cves']) - 6} more)" if len(top["kev_cves"]) > 6 else ""
        L.append(f"      Actively exploited (KEV): {shown}{more}")
    if top["overdue"]:
        L.append("      At least one CISA deadline on this package has already passed.")
    L += ["", "  Full ranking:", "",
          f"  {'#':>2}  {'package':<34}{'worst':>7}{'hosts':>7}{'CVEs':>7}"
          f"{'KEV':>6}  flags"]
    for i, p in enumerate(pkgs, 1):
        flags = []
        if p["overdue"]:
            flags.append("OVERDUE")
        if p["critical_assets"]:
            flags.append(f"{p['critical_assets']} critical host(s)")
        L.append(f"  {i:>2}. {p['product']:<34}{p['worst_action_score']:>7.0f}"
                 f"{p['assets_affected']:>7}{p['cve_count']:>7}"
                 f"{len(p['kev_cves']):>6}  {', '.join(flags)}")
    L += ["", "  Ranking note: packages are ranked by their worst single action, not "
              "by total CVE volume. Volume would put a browser that is 40 releases "
              "behind above an actively-exploited firewall, which is the failure "
              "mode this tool exists to correct."]
    return L


def _group(f, spec, actions, as_of) -> List[str]:
    key = spec.get("group_by") or "department"
    groups = f.get("groups", [])
    totals = f.get("group_asset_totals", {})
    if not groups:
        return ["No findings matched the filters."]
    top = groups[0]
    L = [f"EXPOSURE BY {key.upper()} — ranked by worst single remediation action.", "",
         f"  Highest: {top[key]} — worst action scores "
         f"{top['worst_action_score']:.0f}/100 ({top['top_action']}), with "
         f"{top['kev_cves']} actively-exploited CVEs across "
         f"{top['assets_affected']} of {totals.get(top[key], '?')} assets "
         f"({top['critical_assets_affected']} business-critical).", "",
         f"  {'unit':<14}{'worst':>7}{'actions':>9}{'KEV act':>9}{'KEV CVEs':>10}"
         f"{'assets':>9}{'crit':>6}{'overdue':>9}"]
    for g in groups:
        L.append(f"  {str(g[key]):<14}{g['worst_action_score']:>7.0f}"
                 f"{g['actions']:>9}{g['kev_actions']:>9}{g['kev_cves']:>10}"
                 f"{str(g['assets_affected']) + '/' + str(totals.get(g[key], '?')):>9}"
                 f"{g['critical_assets_affected']:>6}{g['overdue_actions']:>9}")
    L += ["", "  'worst' is the highest-scoring single action in that unit, so a large "
              "unit cannot outrank a smaller one purely by having more machines."]
    return L


def _top_asset(f, actions, rows, as_of) -> List[str]:
    ranked = f.get("ranked_assets", [])
    if not ranked:
        return ["No assets matched the filters."]
    t = ranked[0]
    L = [f"HIGHEST-RISK ASSET: {t['asset_id']} ({t['hostname']})", "",
         f"  Department        : {t['department']}",
         f"  Type              : {t['asset_type']}",
         f"  Criticality       : {t['criticality']}",
         f"  Remediation items : {t['actions']}",
         f"  Applicable CVEs   : {t['cve_count']} ({t['kev_cves']} actively exploited)",
         f"  Top action score  : {t['top_score']:.0f}/100", "",
         "  WHY IT RANKS FIRST:"]
    if actions:
        for line in actions[0].get("score_rationale", []):
            L.append(f"    - {line}")
    L += [""] + _actions_block(actions, as_of,
                               f"  WHAT TO DO ON {t['asset_id']}", 8)
    if rows:
        L += [""] + _evidence_block(rows, as_of,
                                    "  SAMPLE CVE EVIDENCE (worst first)")
    L += ["", "  Runners-up:"]
    for a in ranked[1:5]:
        L.append(f"    {a['asset_id']:<12} {a['hostname']:<30} "
                 f"top {a['top_score']:>5.0f}  actions {a['actions']:>2}  "
                 f"KEV CVEs {a['kev_cves']:>3}")
    return L


def _what_if(f, actions, as_of) -> List[str]:
    if "error" in f:
        return [f["error"]]
    L = [f"COUNTERFACTUAL — patching {f['product']} fleet-wide", "",
         f"  Versions currently deployed : {', '.join(f['versions_present'])}",
         f"  Hosts affected              : {len(f['assets_affected'])} "
         f"({', '.join(f['assets_affected'])})",
         f"  Remediation actions closed  : {f['actions_closed']} of "
         f"{f['fleet_actions_before']} fleet-wide "
         f"-> {f['fleet_actions_after']} remaining",
         f"  Applicable CVEs removed     : {f['distinct_cves_removed']}",
         f"  Fleet distinct CVEs         : {f['fleet_distinct_cves_before']} -> "
         f"{f['fleet_distinct_cves_after']} "
         f"(net reduction {f['net_cve_reduction']})"]
    if f["kev_cves_removed"]:
        shown = ", ".join(f["kev_cves_removed"][:8])
        more = (f" (+{len(f['kev_cves_removed']) - 8} more)"
                if len(f["kev_cves_removed"]) > 8 else "")
        L.append(f"  Actively-exploited CVEs closed: {len(f['kev_cves_removed'])} "
                 f"— {shown}{more}")
    L += ["", "  Note: 'net reduction' can be smaller than 'CVEs removed' when the "
              "same CVE also affects another package still deployed elsewhere.", ""]
    L += _actions_block(actions, as_of, "  ACTIONS THIS CLOSES", 10)
    return L


def _stale(f) -> List[str]:
    assets = f.get("assets", [])
    L = [f"ASSETS NOT SCANNED IN {f['threshold_days']}+ DAYS THAT ALSO HAVE FINDINGS",
         f"(evaluated as of {f['as_of']})", ""]
    if not assets:
        L.append("  None matched.")
    else:
        L.append(f"  {'asset':<12}{'last scan':<12}{'age':>6}{'crit':>10}"
                 f"{'actions':>9}{'KEV CVEs':>10}{'maxCVSS':>9}")
        for a in assets:
            age = "?" if a["days_since_scan"] is None else f"{a['days_since_scan']}d"
            L.append(f"  {a['asset_id']:<12}{a['last_scan_date'] or '-':<12}"
                     f"{age:>6}{a['criticality']:>10}"
                     f"{a['actions']:>9}{a['kev_cves']:>10}{a['max_cvss']:>9}")
    silent = f.get("stale_with_no_findings", [])
    if silent:
        L += ["", f"  ALSO: {len(silent)} stale asset(s) have NO findings at all. "
                  f"That is not the same as being clean — it may mean we have no "
                  f"usable data for them:"]
        for a in silent:
            L.append(f"    {a['asset_id']:<12} last scan {a['last_scan_date']} "
                     f"({a['days_since_scan']}d, {a['criticality']})")
    return L


def _coverage(f) -> List[str]:
    L = ["WHAT THIS ANSWER DOES NOT COVER", "",
         f"  Products in inventory : {f['products_total']}",
         f"  Products assessed     : {f['products_mapped']}",
         f"  Products NOT assessed : {len(f['products_unmapped'])}", ""]
    for name, why in f["products_unmapped"].items():
        L.append(f"    - {name}")
        L.append(f"        {why}")
    L += ["", f"  Operating systems: {f['os_matching']}", "",
          "  Unassessed software instances by reason:"]
    for k, v in f["gap_instances_by_kind"].items():
        L.append(f"    {k:<24} {v}")
    if f.get("integrity_notes"):
        L += ["", "  DATA INTEGRITY NOTES:"]
        for n in f["integrity_notes"]:
            L.append(f"    ! {n}")
    L += ["", "  Absence of a finding for these is NOT evidence of safety. It means "
              "we did not check."]
    return L


def _count(f, spec, actions, as_of) -> List[str]:
    bits = []
    if spec.get("department"):
        bits.append(spec["department"])
    if spec.get("asset_type"):
        bits.append(spec["asset_type"].replace("_", " ") + "s")
    scope = " ".join(bits) if bits else "fleet"
    qual = "actively exploited (KEV) " if spec.get("kev_only") else ""
    L = [f"COUNT — {scope}, {qual}exposure", "",
         f"  Assets affected     : {len(f['asset_ids'])}  "
         f"({', '.join(f['asset_ids']) if f['asset_ids'] else 'none'})",
         f"  Remediation actions : {f['remediation_actions']}",
         f"  Distinct CVEs       : {f['distinct_cves']}",
         f"  Actively exploited  : {f['kev_cves']} CVE(s)", ""]
    L += _actions_block(actions, as_of, "  ACTIONS", 10)
    return L


def _cve_level(f, spec, rows, as_of) -> List[str]:
    scope = spec.get("asset_type") or "fleet"
    L = [f"CVE LIST — {scope.replace('_', ' ')}, sorted by {spec.get('sort_by')}", "",
         f"  Matching findings : {f['total_matching']} (showing {f['shown']})",
         f"  Distinct assets   : {f['distinct_assets']}",
         f"  Distinct CVEs     : {f['distinct_cves']}",
         f"  Actively exploited: {f['kev_count']}", ""]
    L += _evidence_block(rows, as_of, "  FINDINGS")
    return L


def _generic(f, actions, as_of) -> List[str]:
    L = ["EXPOSURE", "",
         f"  Remediation actions : {f['remediation_actions']} "
         f"(showing {f['shown']})",
         f"  Assets affected     : {f['distinct_assets']}",
         f"  Distinct CVEs       : {f['distinct_cves']} "
         f"({f['kev_cves']} actively exploited)",
         f"  Underlying findings : {f['underlying_findings']} asset-CVE pairs", ""]
    L += _actions_block(actions, as_of, "  RANKED ACTIONS")
    return L
