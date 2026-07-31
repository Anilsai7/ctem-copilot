"""Cross-reference assets against vulnerability feeds.

Design note -- the verification pass
------------------------------------
NVD's `virtualMatchString` query already performs version-range matching
server-side. We could simply trust it. Instead, every CVE that NVD returns is
*independently re-checked* locally against the raw CPE configuration nodes
using our own version comparator.

That gives two independent signals per candidate finding:

    NVD says applicable + we confirm  -> CONFIRMED
    NVD says applicable + we can't    -> LIKELY   (surfaced, not hidden)
    mapped but version unusable       -> UNCERTAIN
    no CPE mapping / lookup failed    -> coverage gap, no finding emitted

The point is not that our comparator is better than NVD's. It is that when
two independent methods disagree, an analyst should see the disagreement
rather than a single confident number. Findings that only one method supports
are still shown, just labelled and ranked lower.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from . import catalog, feeds, versions

CONFIRMED = "CONFIRMED"
LIKELY = "LIKELY"
UNCERTAIN = "UNCERTAIN"


@dataclass
class Finding:
    asset_id: str
    hostname: str
    department: str
    criticality: str
    asset_type: str
    last_scan_date: str
    product: str
    installed_version: str
    cpe: str
    cve_id: str
    cvss_score: Optional[float]
    cvss_severity: str
    cvss_vector: Optional[str]
    cvss_metric: Optional[str]
    cvss_source: Optional[str]
    description: str
    in_kev: bool
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    kev_ransomware: Optional[str] = None
    kev_required_action: Optional[str] = None
    confidence: str = CONFIRMED
    evidence: List[str] = field(default_factory=list)
    caveats: List[str] = field(default_factory=list)
    # populated by score.py
    risk_score: float = 0.0
    ranked_score: float = 0.0
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    score_rationale: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CoverageGap:
    asset_id: str
    product: str
    installed_version: str
    reason: str
    kind: str  # unmapped | lookup_failed | unparseable_version | out_of_scope


def _cpe_parts(criteria: str) -> List[str]:
    return criteria.split(":")


def _verify_locally(cve: dict, ident: catalog.CpeIdentity, installed: str) -> tuple:
    """Re-check applicability against raw CPE nodes.

    Returns (verdict, evidence_strings) where verdict is True (confirmed
    vulnerable), False (ranges exclude this version), or None (inconclusive).
    """
    evidence: List[str] = []
    saw_product = False
    verdict = None

    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                parts = _cpe_parts(m.get("criteria", ""))
                if len(parts) < 6:
                    continue
                vendor, product, cpe_ver = parts[3], parts[4], parts[5]
                if vendor != ident.vendor or product != ident.product:
                    continue
                saw_product = True

                has_range = any(
                    k in m for k in (
                        "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding", "versionEndExcluding")
                )
                if has_range:
                    ok = versions.in_range(
                        installed,
                        m.get("versionStartIncluding"), m.get("versionStartExcluding"),
                        m.get("versionEndIncluding"), m.get("versionEndExcluding"),
                    )
                    bounds = ", ".join(
                        f"{k.replace('version', '')}={v}"
                        for k, v in m.items() if k.startswith("version")
                    )
                    if ok:
                        evidence.append(f"CPE range match: {installed} satisfies [{bounds}]")
                        return True, evidence
                    if ok is None:
                        evidence.append(f"CPE range [{bounds}] not comparable to {installed}")
                        verdict = None
                else:
                    exact = versions.matches_cpe_version(installed, cpe_ver)
                    if exact:
                        evidence.append(f"CPE exact version match: {m['criteria']}")
                        return True, evidence
                    if exact is None and cpe_ver in ("*", "-"):
                        evidence.append(
                            f"CPE {m['criteria']} covers all versions (no version bound given)")
                        verdict = None

    if not saw_product:
        evidence.append(
            f"NVD returned this CVE for {ident.prefix} but no matching vulnerable "
            f"CPE node was found locally")
    return verdict, evidence


def build_findings(assets: List[dict], nvd: feeds.NvdClient, kev_index: Dict[str, dict],
                   progress=None) -> tuple:
    """Produce (findings, coverage_gaps, stats)."""
    findings: List[Finding] = []
    gaps: List[CoverageGap] = []
    stats = {"lookups": 0, "cache_only": 0, "cves_seen": 0}

    for asset in assets:
        for sw in asset.get("installed_software", []):
            name, ver = sw.get("name"), sw.get("version")
            ident = catalog.lookup(name)

            if ident is None:
                gaps.append(CoverageGap(
                    asset["asset_id"], name, ver,
                    catalog.UNMAPPED_REASONS.get(
                        name, "No CPE mapping defined for this product."),
                    "unmapped"))
                continue

            if versions.parse(ver) is None:
                gaps.append(CoverageGap(
                    asset["asset_id"], name, ver,
                    "Installed version string could not be parsed.",
                    "unparseable_version"))
                continue

            match_str = ident.virtual_match(ver)
            data = nvd.cves_for_cpe(match_str)
            stats["lookups"] += 1
            if progress:
                progress(asset["asset_id"], name, ver,
                         None if data is None else data.get("totalResults", 0))

            if data is None:
                gaps.append(CoverageGap(
                    asset["asset_id"], name, ver,
                    "NVD lookup did not complete; this product was NOT assessed. "
                    "Absence of findings here does not mean absence of risk.",
                    "lookup_failed"))
                continue

            # A mapped product that returns nothing is ambiguous: either it is
            # genuinely clean, or our CPE/version form does not match NVD's
            # (Oracle's 1.8.0:update_271 vs an inventory's 8.0.302 is the
            # classic case). Those two must not look identical to an analyst,
            # so a zero-result lookup is recorded as a soft signal rather than
            # silently counted as "no risk".
            if not (data.get("vulnerabilities") or []):
                gaps.append(CoverageGap(
                    asset["asset_id"], name, ver,
                    f"NVD returned 0 CVEs for {match_str}. This may mean the "
                    f"version is genuinely unaffected, or that the CPE/version "
                    f"form does not match NVD's. Verify before treating as clean.",
                    "zero_results"))
                continue

            for item in data.get("vulnerabilities", []) or []:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue
                stats["cves_seen"] += 1

                verdict, evidence = _verify_locally(cve, ident, ver)
                caveats: List[str] = []
                if verdict is True:
                    confidence = CONFIRMED
                elif verdict is None:
                    confidence = LIKELY
                    caveats.append(
                        "NVD returned this CVE as applicable to the installed version, "
                        "but independent local re-check of the CPE ranges was "
                        "inconclusive. Verify against the vendor advisory before patching.")
                else:
                    # Local check actively contradicts NVD. Keep it, flag loudly.
                    confidence = UNCERTAIN
                    caveats.append(
                        "CONFLICT: NVD returned this CVE for the installed version, but "
                        "local CPE range evaluation excludes it. Treat as unverified.")

                cvss = feeds.extract_cvss(cve)
                if cvss["score"] is None:
                    caveats.append("No CVSS base score published in NVD for this CVE.")
                if cvss["source"] == "Secondary":
                    caveats.append(
                        "CVSS score is from a secondary (CNA) source; NVD has not "
                        "published its own analysis.")

                k = kev_index.get(cve_id)
                evidence.append(f"NVD virtualMatchString={match_str}")

                findings.append(Finding(
                    asset_id=asset["asset_id"],
                    hostname=asset["hostname"],
                    department=asset["department"],
                    criticality=asset["criticality"],
                    asset_type=asset["asset_type"],
                    last_scan_date=asset.get("last_scan_date", ""),
                    product=name,
                    installed_version=ver,
                    cpe=ident.prefix,
                    cve_id=cve_id,
                    cvss_score=cvss["score"],
                    cvss_severity=cvss["severity"],
                    cvss_vector=cvss["vector"],
                    cvss_metric=cvss["metric"],
                    cvss_source=cvss["source"],
                    description=feeds.english_description(cve)[:400],
                    in_kev=bool(k),
                    kev_date_added=(k or {}).get("dateAdded"),
                    kev_due_date=(k or {}).get("dueDate"),
                    kev_ransomware=(k or {}).get("knownRansomwareCampaignUse"),
                    kev_required_action=(k or {}).get("requiredAction"),
                    confidence=confidence,
                    evidence=evidence,
                    caveats=caveats,
                ))

    return findings, gaps, stats
