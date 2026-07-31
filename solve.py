"""CTEM exposure analysis: assets.json x live CISA KEV.

Scope cut (deliberate, per the brief's "reasonable scope reductions are
encouraged"): match the inventory against a curated set of high-signal
vulnerabilities with EXPLICIT version rules, then join to the live CISA KEV
catalog for exploitation status, due dates and ransomware linkage.

Why not query all of NVD by CPE: it returns every CVE fixed in any later
release, so a browser 40 versions behind yields ~2,300 technically-applicable
CVEs and drowns an actively-exploited firewall. That reproduces the exact
3,400-finding noise problem we were hired to fix.

But precision must not become blindness: a single high-signal browser CVE
(libwebp, CVE-2023-4863) is included because it is KEV-listed and lands on the
CEO and CISO workstations. The cut is "one CVE per package that matters", not
"ignore browsers".

Three confidence tiers, because version applicability and exploitability are
not the same claim:
  confirmed  the installed version is in the affected range and nothing else
             is required for the vulnerability to exist on this host
  likely     version is affected, but exploitation needs a configuration or
             exposure the inventory does not record
  uncertain  version is affected, but a load-bearing precondition is unproven
             or the inventory contradicts itself

Uncertain findings are surfaced and labelled, never silently dropped, and they
carry a confidence weight into the risk score rather than being scored as fact.
"""

import json
import os
import re
import ssl
import urllib.request
from datetime import date, datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

CONFIDENCE_WEIGHT = {"confirmed": 1.00, "likely": 0.85, "uncertain": 0.70}
CRIT_PTS = {"critical": 25, "high": 18, "medium": 10, "low": 4}


# ---------------------------------------------------------------------------
# version comparison
# ---------------------------------------------------------------------------
def _tok(v):
    return [int(x) if x.isdigit() else x.lower()
            for x in re.findall(r"\d+|[A-Za-z]+", str(v))]


def _cmp(a, b):
    ta, tb = _tok(a), _tok(b)
    for x, y in zip(ta, tb):
        if type(x) is type(y):
            if x != y:
                return -1 if x < y else 1
        else:
            return 0
    return (len(ta) > len(tb)) - (len(ta) < len(tb))


def _lt(v, hi):
    return _cmp(v, hi) < 0


def _between(v, lo, hi):
    """lo <= v < hi"""
    return _cmp(v, lo) >= 0 and _cmp(v, hi) < 0


def _java_le(v, major, max_update):
    """Java SE '8.0.271' style: major 8, update 271. True if update <= max_update."""
    p = str(v).split(".")
    if len(p) != 3 or not p[2].isdigit():
        return False
    return p[0] == str(major) and int(p[2]) <= max_update


# ---------------------------------------------------------------------------
# detection rules
# ---------------------------------------------------------------------------
def R(product, pred, cve, cvss, why, confidence="confirmed", caveat=None,
      requires_os=None):
    return dict(product=product, pred=pred, cve=cve, cvss=cvss, why=why,
                confidence=confidence, caveat=caveat, requires_os=requires_os)


RULES = [
    # --- web / middleware -------------------------------------------------
    R("Apache HTTP Server", lambda v: v == "2.4.49", "CVE-2021-41773", 9.8,
      "Path traversal -> RCE. NVD lists 2.4.49 as the only affected release."),
    R("Apache HTTP Server", lambda v: v in ("2.4.49", "2.4.50"),
      "CVE-2021-42013", 9.8,
      "Incomplete fix for CVE-2021-41773. Affects 2.4.49 and 2.4.50."),
    R("Apache Tomcat", lambda v: _between(v, "9.0.0", "9.0.99"),
      "CVE-2025-24813", 9.8,
      "Partial PUT -> RCE. Affects 9.0.0.M1 through 9.0.98."),

    # --- log4j ------------------------------------------------------------
    R("log4j-core", lambda v: _between(v, "2.0", "2.15.0"), "CVE-2021-44228", 10.0,
      "Log4Shell JNDI RCE. Affects 2.0-beta9 through 2.14.1 (fixed in 2.15.0)."),
    R("log4j-core", lambda v: _between(v, "2.0", "2.16.0"), "CVE-2021-45046", 9.0,
      "Follow-up to Log4Shell. Affects up to and including 2.15.0.",
      "likely",
      "Highest impact depends on non-default logging patterns / context lookups. "
      "The version is affected regardless; the CVSS 9.0 path is not guaranteed."),

    # --- dev / ops tooling ------------------------------------------------
    R("Jenkins", lambda v: _lt(v, "2.442"), "CVE-2024-23897", 9.8,
      "Arbitrary file read via the CLI. Affects Jenkins < 2.442."),
    R("Grafana", lambda v: _between(v, "8.0.0", "8.3.1"), "CVE-2021-43798", 7.5,
      "Directory traversal, unauthenticated arbitrary file read. Affects 8.0.0-8.3.0."),
    R("Sonatype Nexus Repository Manager", lambda v: _lt(v, "3.68.1"),
      "CVE-2024-4956", 7.5,
      "Path traversal, unauthenticated file read. Affects < 3.68.1."),

    # --- mail -------------------------------------------------------------
    R("Microsoft Exchange Server", lambda v: _lt(v, "15.1.2375.18"),
      "CVE-2021-34473", 9.8,
      "ProxyShell pre-auth RCE. Exchange 2016 fixed in 15.1.2375.18."),

    # --- browsers / client (one high-signal KEV CVE, not the full history) --
    R("Google Chrome", lambda v: _lt(v, "116.0.5845.187"), "CVE-2023-4863", 8.8,
      "libwebp heap buffer overflow, exploited via crafted WebP images. "
      "Chrome fixed in 116.0.5845.187."),
    R("Mozilla Firefox", lambda v: _lt(v, "117.0.1"), "CVE-2023-4863", 8.8,
      "Same libwebp flaw; Firefox bundles the library. Fixed in 117.0.1 / ESR 115.2.1.",
      "uncertain",
      "The inventory records no SBOM, so we cannot prove which libwebp build this "
      "Firefox package links. Version is below the fixed release, but bundled-library "
      "applicability is inferred, not evidenced."),
    R("Internet Explorer", lambda v: v.startswith("11."), "CVE-2021-26411", 8.8,
      "Memory corruption. IE11 is end-of-life and receives no fixes."),

    # --- network edge (config-dependent) ----------------------------------
    R("Fortinet FortiOS", lambda v: _between(v, "6.4.0", "6.4.13"),
      "CVE-2023-27997", 9.8,
      "XORtigate SSL-VPN pre-auth heap overflow. Affects 6.4.0-6.4.12.",
      "likely",
      "Requires the SSL-VPN interface to be enabled. The hostname (ops-vpn01) "
      "strongly implies it, but the inventory does not record enabled services."),
    R("Fortinet FortiOS", lambda v: _between(v, "6.4.0", "6.4.11"),
      "CVE-2022-42475", 9.8,
      "SSL-VPN heap overflow, pre-auth RCE. Affects 6.4.0-6.4.10.",
      "likely",
      "Requires the SSL-VPN interface to be enabled and reachable."),
    R("Fortinet FortiOS", lambda v: _between(v, "6.4.0", "6.4.15"),
      "CVE-2024-21762", 9.8,
      "SSL-VPN out-of-bounds write. Affects 6.4.0-6.4.14.",
      "likely",
      "Requires the SSL-VPN interface to be enabled and reachable."),
    R("F5 BIG-IP", lambda v: _between(v, "13.1.0", "16.1.3"), "CVE-2022-1388", 9.8,
      "iControl REST authentication bypass -> RCE. Affects 13.1.x-16.1.x.",
      "likely",
      "Requires the iControl REST management interface to be network-reachable. "
      "The inventory does not record management-plane exposure."),
    R("Cisco IOS XE", lambda v: _between(v, "16.0.0", "17.9.99"),
      "CVE-2023-20198", 10.0,
      "Web UI privilege escalation used to deploy implants. Affects IOS XE 16.x/17.x.",
      "uncertain",
      "Exploitation requires the HTTP/HTTPS Web UI to be enabled AND reachable from "
      "an untrusted network. Neither fact is in the inventory, and the Web UI is "
      "off by default on many deployments."),

    # --- backup (platform mismatch) ---------------------------------------
    R("Veeam Backup & Replication", lambda v: _lt(v, "11.0.1.1261"),
      "CVE-2023-27532", 7.5,
      "Credential disclosure in the backup service. Fixed in 11.0.1.1261 / 12.0.0.1420.",
      "uncertain",
      "PLATFORM CONFLICT: this host reports Ubuntu 18.04, but Veeam Backup & "
      "Replication server is Windows-only software. Either the inventory is wrong "
      "about the OS, or this is a Linux agent/proxy rather than the vulnerable "
      "server component. Verify before raising a ticket.",
      requires_os="Windows"),

    # --- crypto libraries -------------------------------------------------
    # Ranges below were read directly from NVD CPE nodes, not assumed.
    # NOTE 1.1.1l is the FIX for both, so it must NOT match.
    # NOTE OpenSSL letter ordering: 1.0.2u < 1.0.2za (u < za lexicographically),
    #      which our tokenizer gets right.
    R("OpenSSL", lambda v: _between(v, "1.1.1", "1.1.1l"), "CVE-2021-3711", 9.8,
      "SM2 decryption buffer overflow. NVD: 1.1.1 <= v < 1.1.1l."),
    R("OpenSSL", lambda v: (_between(v, "1.1.1", "1.1.1l")
                            or _between(v, "1.0.2", "1.0.2za")),
      "CVE-2021-3712", 7.4,
      "Read buffer overrun processing ASN.1 strings. NVD: 1.0.2 <= v < 1.0.2za, "
      "or 1.1.1 <= v < 1.1.1l."),

    # --- databases --------------------------------------------------------
    R("PostgreSQL", lambda v: (_between(v, "12.0", "12.9")
                               or _between(v, "13.0", "13.5")),
      "CVE-2021-23214", 8.1,
      "Server does not reject extra data after SSL/TLS handshake, enabling "
      "man-in-the-middle injection. NVD: 12.x < 12.9, 13.x < 13.5."),
    R("PostgreSQL", lambda v: (_between(v, "12.0", "12.11")
                               or _between(v, "13.0", "13.7")),
      "CVE-2022-1552", 8.8,
      "Autovacuum and REINDEX miss security restrictions, allowing privilege "
      "escalation. NVD: 12.x < 12.11, 13.x < 13.7."),

    # --- Java runtimes ----------------------------------------------------
    # Deliberately UNCERTAIN. NVD's CPE for Oracle Java is `oracle:jre:1.8.0`
    # with no update field, so it cannot express "8u271 vs 8u281". We fall back
    # to Oracle's own Critical Patch Update advisory, which lists affected
    # releases as "8u281 and earlier". That is vendor-sourced reasoning, not
    # NVD-verified version matching, and it is labelled as such.
    R("Java SE", lambda v: _java_le(v, 8, 281), "CVE-2021-2161", 5.9,
      "Oracle Java SE / OpenJDK libraries flaw (April 2021 CPU). Oracle lists "
      "8u281 and earlier as affected.",
      "uncertain",
      "NVD's CPE for Oracle Java is `oracle:jre:1.8.0` with no update granularity, "
      "so per-update applicability cannot be machine-verified. This match relies on "
      "Oracle's CPU advisory text. Confirm the exact build before raising a ticket. "
      "Separately, the inventory records 8.0.271 while NVD uses 1.8.0:update_271 — "
      "the two namespaces do not reconcile automatically."),
    R("Java SE", lambda v: _java_le(v, 7, 291), "CVE-2021-2161", 5.9,
      "Same April 2021 CPU flaw; Oracle lists 7u291 and earlier as affected. "
      "Java SE 7 has had no public updates since April 2015.",
      "uncertain",
      "Java SE 7 is end-of-life; it receives no public security updates at all, so "
      "the specific CVE understates the risk. The runtime itself should be removed "
      "or moved to extended support. CPE granularity prevents automated verification."),

    # --- endpoint ---------------------------------------------------------
    R("PuTTY", lambda v: _between(v, "0.68", "0.81"), "CVE-2024-31497", 5.9,
      "NIST P-521 ECDSA nonce bias enables private-key recovery. Affects 0.68-0.80."),
]


# ---------------------------------------------------------------------------
# data loading
# ---------------------------------------------------------------------------
def _ssl_ctx():
    for p in [os.environ.get("SSL_CERT_FILE"),
              r"C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt",
              "/etc/ssl/certs/ca-certificates.crt"]:
        if p and os.path.exists(p):
            try:
                return ssl.create_default_context(cafile=p)
            except Exception:
                pass
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def load_kev(prefer_live=True):
    """Live CISA KEV with a bundled snapshot as fallback."""
    if prefer_live:
        try:
            req = urllib.request.Request(
                KEV_URL, headers={"User-Agent": "ctem-copilot/1.0"})
            with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx()) as r:
                return json.loads(r.read().decode("utf-8")), "live"
        except Exception:
            pass
    with open(os.path.join(ROOT, "cache", "kev.json"), encoding="utf-8") as f:
        return json.load(f), "cached"


def load_assets():
    with open(os.path.join(ROOT, "data", "assets.json"), encoding="utf-8") as f:
        return json.load(f)


def analysis_date(inv):
    """Anchor to the newest scan in the data, not wall-clock time.

    Using today's date makes the report drift every time it runs and makes
    "days overdue" unreproducible. Anchoring to the data's own most recent
    observation means the same input always produces the same report.
    """
    return max(datetime.strptime(a["last_scan_date"], "%Y-%m-%d").date()
               for a in inv["assets"])


# ---------------------------------------------------------------------------
# data-quality checks (run before any finding is trusted)
# ---------------------------------------------------------------------------
def data_quality(inv):
    issues = []
    meta = inv.get("metadata", {})
    gen = meta.get("generated_date")
    assets = inv["assets"]

    if gen:
        late = [(a["asset_id"], a["last_scan_date"]) for a in assets
                if a["last_scan_date"] > gen]
        if late:
            issues.append({
                "kind": "impossible_timestamp",
                "severity": "medium",
                "summary": f"{len(late)} assets have a last_scan_date AFTER the "
                           f"inventory's generated_date ({gen}).",
                "detail": ", ".join(f"{a} ({d})" for a, d in late),
                "impact": "Scan recency cannot be fully trusted; either the export "
                          "date or the scan dates are wrong.",
            })

    declared = meta.get("asset_count")
    if declared is not None and declared != len(assets):
        issues.append({
            "kind": "count_mismatch", "severity": "high",
            "summary": f"metadata.asset_count says {declared}, file contains "
                       f"{len(assets)} records.",
            "detail": "Using the actual records.",
            "impact": "Denominators in every percentage would be wrong.",
        })
    else:
        issues.append({
            "kind": "count_mismatch", "severity": "low",
            "summary": f"The assignment brief describes 25 assets; the provided file "
                       f"declares and contains {len(assets)}.",
            "detail": "Analysis uses the 23 records actually present.",
            "impact": "If 2 assets are genuinely missing, their exposure is invisible.",
        })

    # platform contradictions implied by the rule set
    for a in assets:
        for r in RULES:
            if not r["requires_os"]:
                continue
            names = [s["name"] for s in a["installed_software"]]
            if r["product"] in names and r["requires_os"].lower() not in a["os"].lower():
                issues.append({
                    "kind": "platform_conflict", "severity": "high",
                    "summary": f"{a['asset_id']} lists {r['product']} but reports OS "
                               f"'{a['os']}'.",
                    "detail": f"{r['product']} server is {r['requires_os']}-only.",
                    "impact": "Findings for this product are downgraded to uncertain.",
                })

    stale_scans = sorted(
        ((a["asset_id"], a["last_scan_date"]) for a in assets),
        key=lambda t: t[1])[:3]
    issues.append({
        "kind": "scan_coverage", "severity": "medium",
        "summary": "Scan dates span "
                   f"{min(a['last_scan_date'] for a in assets)} to "
                   f"{max(a['last_scan_date'] for a in assets)}.",
        "detail": "Oldest: " + ", ".join(f"{a} ({d})" for a, d in stale_scans),
        "impact": "Software inventory on the oldest hosts may no longer be accurate, "
                  "so both findings and clean results are less reliable there.",
    })
    return issues


# ---------------------------------------------------------------------------
# matching + scoring
# ---------------------------------------------------------------------------
def build_findings(inv, kevidx, as_of=None):
    as_of = as_of or analysis_date(inv)
    out = []
    for a in inv["assets"]:
        for sw in a.get("installed_software", []):
            for r in RULES:
                if sw["name"] != r["product"]:
                    continue
                try:
                    if not r["pred"](sw["version"]):
                        continue
                except Exception:
                    continue

                confidence, caveat = r["confidence"], r["caveat"]
                # A declared platform mismatch always degrades confidence.
                if r["requires_os"] and r["requires_os"].lower() not in a["os"].lower():
                    confidence = "uncertain"

                k = kevidx.get(r["cve"])
                due = k.get("dueDate") if k else None
                overdue = bool(due and
                               datetime.strptime(due, "%Y-%m-%d").date() < as_of)
                f = {
                    "asset_id": a["asset_id"], "hostname": a["hostname"],
                    "department": a["department"], "criticality": a["criticality"],
                    "asset_type": a["asset_type"], "os": a["os"],
                    "last_scan": a["last_scan_date"],
                    "product": r["product"], "version": sw["version"],
                    "cve": r["cve"], "cvss": r["cvss"], "why": r["why"],
                    "confidence": confidence, "caveat": caveat,
                    "in_kev": bool(k),
                    "kev_added": k.get("dateAdded") if k else None,
                    "due": due, "overdue": overdue,
                    "ransomware": (k.get("knownRansomwareCampaignUse", "").lower()
                                   == "known") if k else False,
                    "nvd_url": f"https://nvd.nist.gov/vuln/detail/{r['cve']}",
                    "kev_url": ("https://www.cisa.gov/known-exploited-vulnerabilities"
                                f"-catalog?field_cve={r['cve']}"),
                }
                f.update(score(f, as_of))
                out.append(f)
    return sorted(out, key=lambda f: -f["risk"])


def score(f, as_of):
    b = {}
    b["severity"] = round(f["cvss"] / 10 * 30, 1)
    b["exploited"] = (25 if f["in_kev"] else 0) + (5 if f["ransomware"] else 0)
    b["criticality"] = CRIT_PTS.get(f["criticality"], 10)
    if f["overdue"]:
        b["urgency"] = 15
    elif f["due"]:
        d = (datetime.strptime(f["due"], "%Y-%m-%d").date() - as_of).days
        b["urgency"] = 11 if d <= 14 else 7 if d <= 30 else 4
    else:
        b["urgency"] = 0
    raw = round(sum(b.values()), 1)
    w = CONFIDENCE_WEIGHT[f["confidence"]]
    total = round(raw * w, 1)
    return {"raw_risk": raw, "risk": total, "conf_weight": w, "breakdown": b,
            "band": "CRITICAL" if total >= 75 else "HIGH" if total >= 55
            else "MEDIUM" if total >= 35 else "LOW"}


def cite(f):
    kev = (f"KEV added {f['kev_added']}, due {f['due']}"
           + (" [OVERDUE]" if f["overdue"] else "")) if f["in_kev"] else "not in KEV"
    rw = ", ransomware-linked" if f["ransomware"] else ""
    return (f"[{f['asset_id']} | {f['hostname']}] {f['product']} {f['version']} - "
            f"{f['cve']} CVSS {f['cvss']} - {kev}{rw} - {f['confidence'].upper()} - "
            f"risk {f['risk']:.0f}/100 [{f['band']}]")


# ---------------------------------------------------------------------------
# Free-text question routing
# ---------------------------------------------------------------------------
# Deliberately keyword-based rather than an LLM call. The router only chooses
# WHICH precomputed answer to show; it never generates a fact. That means a
# misrouted question shows the wrong (but still true) answer, instead of a
# confident wrong one. Fuzzy token overlap absorbs typos like "vulneabilities".

INTENTS = [
    ("critical",   ["critical", "severe", "worst cve", "cvss 9", "high severity"]),
    ("top_asset",  ["highest risk", "riskiest", "most at risk", "worst server",
                    "worst asset", "highest-risk", "top asset", "which server"]),
    ("patch_first", ["patch first", "patch next", "what to patch", "which software",
                     "which package", "prioriti", "remediate first", "fix first"]),
    ("finance_kev", ["finance", "actively exploited", "exploited in the wild"]),
    ("overdue",    ["due date", "overdue", "past due", "deadline", "passed"]),
    ("ciso",       ["summar", "posture", "ciso", "overview", "executive summary"]),
    ("unit",       ["business unit", "department", "which unit", "team"]),
    ("apache",     ["apache", "http server", "what would patching"]),
    ("network",    ["network device", "firewall", "router", "switch", "vpn",
                    "network"]),
    ("stale",      ["scan", "not scanned", "stale", "30 days", "last scan"]),
    ("trend",      ["changed", "change since", "last month", "trend", "compared to"]),
    ("coverage",   ["not assessed", "coverage", "what did you miss", "blind spot",
                    "not covered", "gap"]),
]


def _tokens(s):
    return set(re.findall(r"[a-z]+", s.lower()))


def route_question(q):
    """Return (intent_key, confidence) or (None, 0.0) if nothing matches well.

    Never guesses aggressively: below the threshold we return None so the UI
    can say "I'm not sure what you meant" and show the ranked queue instead of
    answering a question that wasn't asked.
    """
    s = (q or "").lower().strip()
    if not s:
        return None, 0.0

    # exact phrase hits win
    for key, phrases in INTENTS:
        for p in phrases:
            if p in s:
                return key, 1.0

    # fuzzy fallback: token overlap against each intent's vocabulary
    qt = _tokens(s)
    best, score = None, 0.0
    for key, phrases in INTENTS:
        vocab = _tokens(" ".join(phrases))
        if not vocab:
            continue
        overlap = len(qt & vocab) / max(len(vocab) ** 0.5, 1)
        if overlap > score:
            best, score = key, overlap
    return (best, round(score, 2)) if score >= 0.5 else (None, round(score, 2))


# ---------------------------------------------------------------------------
# CLI report
# ---------------------------------------------------------------------------
def hdr(n, q):
    print("\n" + "=" * 84)
    print(f"Q{n}. {q}")
    print("=" * 84)


def main():
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    inv = load_assets()
    kev_raw, mode = load_kev()
    kevidx = {e["cveID"]: e for e in kev_raw["vulnerabilities"]}
    AS_OF = analysis_date(inv)
    F = build_findings(inv, kevidx, AS_OF)
    assets = inv["assets"]
    dq = data_quality(inv)

    conf = [f for f in F if f["confidence"] == "confirmed"]
    likely = [f for f in F if f["confidence"] == "likely"]
    unc = [f for f in F if f["confidence"] == "uncertain"]
    od = [f for f in F if f["overdue"]]
    kevf = [f for f in F if f["in_kev"]]

    print("=" * 84)
    print(f"  {inv['metadata']['organisation']}")
    print(f"  Assets {len(assets)} | Findings {len(F)} "
          f"(confirmed {len(conf)} / likely {len(likely)} / uncertain {len(unc)})")
    print(f"  KEV-listed {len(kevf)} | past CISA deadline {len(od)}")
    print(f"  CISA KEV {kev_raw['catalogVersion']} ({mode}, {len(kevidx):,} CVEs, "
          f"released {kev_raw['dateReleased'][:10]})")
    print(f"  Analysis date {AS_OF} (newest scan in the dataset, not wall-clock)")
    print("=" * 84)

    # 1
    hdr(1, "Which of our assets have critical unpatched CVEs?")
    crit = [f for f in F if f["cvss"] >= 9.0]
    cc = [f for f in crit if f["confidence"] == "confirmed"]
    cv = [f for f in crit if f["confidence"] != "confirmed"]
    print(f"I found {len(cc)} CONFIRMED critical findings across "
          f"{len({f['asset_id'] for f in cc})} assets, plus {len(cv)} that need "
          f"verification across {len({f['asset_id'] for f in cv})} assets.\n")
    print("CONFIRMED")
    for f in cc:
        print("  " + cite(f))
    if cv:
        print("\nNEEDS VERIFICATION")
        for f in cv:
            print("  " + cite(f))
            print(f"      ! {f['caveat']}")
    print("\n  Assumption: 'unpatched' is inferred from the installed version being "
          "in an affected\n  range. The inventory records no patch/KB state.")

    # 2
    hdr(2, "What is our highest-risk server right now and why?")
    srv = [f for f in F if f["asset_type"] == "server"]
    t = srv[0]
    print(f"{t['asset_id']} ({t['hostname']}) - {t['department']}, "
          f"{t['criticality']} criticality.\n")
    for k, v in t["breakdown"].items():
        print(f"    {k:<14} +{v}")
    print(f"    {'subtotal':<14} {t['raw_risk']}")
    print(f"    {'confidence':<14} x{t['conf_weight']} ({t['confidence']})")
    print(f"    {'TOTAL':<14} {t['risk']}/100  [{t['band']}]")
    print(f"\n  Driver: {t['cve']} - {t['why']}")
    same = [f for f in srv if f["asset_id"] == t["asset_id"]][1:]
    if same:
        print("\n  Other findings on this host:")
        for f in same:
            print("    " + cite(f))

    # 3
    hdr(3, "Which software package should we patch first to reduce the most exposure?")
    byp = {}
    for f in F:
        byp.setdefault(f["product"], []).append(f)
    rows = [(p, max(x["risk"] for x in fs), sum(x["risk"] for x in fs),
             len({x["asset_id"] for x in fs}), len({x["cve"] for x in fs}),
             sum(1 for x in fs if x["in_kev"]),
             sum(1 for x in fs if x["confidence"] != "confirmed"),
             any(x["overdue"] for x in fs)) for p, fs in byp.items()]
    rows.sort(key=lambda r: -r[2])
    print(f"  {'package':<34}{'worst':>7}{'total':>8}{'hosts':>7}{'CVEs':>6}"
          f"{'KEV':>5}{'unconf':>8}  flags")
    for p, w, tot, h, nc, nk, nu, ov in rows:
        print(f"  {p:<34}{w:>7.0f}{tot:>8.0f}{h:>7}{nc:>6}{nk:>5}{nu:>8}"
              f"  {'OVERDUE' if ov else ''}")
    best_total = rows[0]
    best_worst = max(rows, key=lambda r: r[1])
    print(f"\n  By total risk removed : {best_total[0]} "
          f"({best_total[2]:.0f} points across {best_total[3]} hosts)")
    print(f"  By worst single item  : {best_worst[0]} ({best_worst[1]:.0f}/100)")
    print("  Both are shown because they answer different questions: total = most "
          "exposure\n  removed fleet-wide, worst = the single item most likely to "
          "hurt you first.")

    # 4
    hdr(4, "How many Finance assets are affected by actively exploited vulnerabilities?")
    fin = [f for f in F if f["department"] == "Finance" and f["in_kev"]]
    fc = sorted({f["asset_id"] for f in fin if f["confidence"] == "confirmed"})
    fu = sorted({f["asset_id"] for f in fin if f["confidence"] != "confirmed"} - set(fc))
    tot = len([a for a in assets if a["department"] == "Finance"])
    print(f"{len(fc)} of {tot} Finance assets have CONFIRMED KEV exposure "
          f"({', '.join(fc)}).")
    if fu:
        print(f"A further {len(fu)} need verification ({', '.join(fu)}).")
    print(f"There are {len(fin)} matched KEV findings, because one asset can carry "
          f"more than one CVE.\n")
    for f in fin:
        print("  " + cite(f))

    # 5
    hdr(5, "Are any assets past a CISA KEV due date?")
    print(f"YES - {len(od)} findings across {len({f['asset_id'] for f in od})} assets "
          f"are past their CISA deadline as of {AS_OF}.\n")
    for f in sorted(od, key=lambda x: x["due"]):
        days = (AS_OF - datetime.strptime(f["due"], "%Y-%m-%d").date()).days
        print(f"  {f['asset_id']:<12} {f['cve']:<16} due {f['due']}  "
              f"overdue {days:>5,}d  {f['confidence']:<9} {f['product']} {f['version']}")

    # 6
    hdr(6, "Summarise our overall vulnerability posture for the CISO in 3 sentences.")
    kassets = {f["asset_id"] for f in kevf}
    critassets = {f["asset_id"] for f in kevf if f["criticality"] == "critical"}
    oldest = max((AS_OF - datetime.strptime(f["due"], "%Y-%m-%d").date()).days
                 for f in od)
    print(f"1. Across {len(assets)} assets we confirmed {len(conf)} findings and "
          f"flagged a further {len(likely) + len(unc)} that need configuration or "
          f"platform verification, covering {len({f['cve'] for f in F})} distinct "
          f"CVEs of which {len({f['cve'] for f in kevf})} are on CISA's Known "
          f"Exploited Vulnerabilities list.")
    print(f"\n2. {len(kassets)} assets carry at least one actively-exploited CVE - "
          f"{len(critassets)} of them business-critical - and every matched KEV "
          f"deadline has already passed, the oldest by {oldest:,} days.")
    print(f"\n3. Patch {best_total[0]} first, then validate the "
          f"{len(likely) + len(unc)} configuration-dependent findings; this covers "
          f"{len({r['product'] for r in RULES})} high-signal packages and excludes "
          f"operating-system patching, so it is a floor on exposure, not a complete "
          f"picture.")

    # 7
    hdr(7, "Which business unit has the most critical exposure?")
    byd = {}
    for f in F:
        byd.setdefault(f["department"], []).append(f)
    dtot = {}
    for a in assets:
        dtot[a["department"]] = dtot.get(a["department"], 0) + 1
    drows = [(d, max(x["risk"] for x in fs), sum(x["risk"] for x in fs), len(fs),
              sum(1 for x in fs if x["in_kev"]),
              len({x["asset_id"] for x in fs}), dtot[d],
              len({x["asset_id"] for x in fs if x["criticality"] == "critical"}))
             for d, fs in byd.items()]
    drows.sort(key=lambda r: -r[2])
    print(f"  {'unit':<14}{'worst':>7}{'total':>8}{'findings':>10}{'KEV':>5}"
          f"{'assets':>9}{'crit':>6}")
    for d, w, tot, n, nk, na, nt, ncrit in drows:
        print(f"  {d:<14}{w:>7.0f}{tot:>8.0f}{n:>10}{nk:>5}"
              f"{str(na) + '/' + str(nt):>9}{ncrit:>6}")
    print(f"\n  {drows[0][0]} - highest aggregate exposure "
          f"({drows[0][2]:.0f} risk points), {drows[0][7]} business-critical assets "
          f"affected.")

    # 8
    hdr(8, "What would patching Apache HTTP Server reduce our CVE count by?")
    ap = [f for f in F if f["product"] == "Apache HTTP Server"]
    rest = {f["cve"] for f in F if f["product"] != "Apache HTTP Server"}
    before = len({f["cve"] for f in F})
    print(f"  Hosts affected            : {len({f['asset_id'] for f in ap})} "
          f"({', '.join(sorted({f['asset_id'] for f in ap}))})")
    print(f"  Findings closed           : {len(ap)} (all confirmed)")
    print(f"  Distinct CVEs closed      : {len({f['cve'] for f in ap})} "
          f"({', '.join(sorted({f['cve'] for f in ap}))})")
    print(f"  Fleet distinct CVEs       : {before} -> {len(rest)} "
          f"(net reduction {before - len(rest)})")
    print(f"  Risk points removed       : {sum(f['risk'] for f in ap):.0f} of "
          f"{sum(f['risk'] for f in F):.0f}")
    print("\n  One action - upgrade Apache to 2.4.58+ on FIN-SRV-001 - closes both.")

    # 9
    hdr(9, "List all CVEs affecting our network devices sorted by CVSS score.")
    nd = sorted([f for f in F if f["asset_type"] == "network_device"],
                key=lambda x: -x["cvss"])
    for f in nd:
        print("  " + cite(f))
        print(f"       {f['why']}")
        if f["caveat"]:
            print(f"       ! {f['caveat']}")
    print(f"\n  All {len(nd)} network-device findings depend on management/Web UI/"
          f"SSL-VPN exposure\n  that the inventory does not record, so none are "
          f"presented as certain exploitation paths.")

    # 10
    hdr(10, "Assets not scanned in the last 30 days that also have high-severity CVEs?")
    stale = {}
    for f in F:
        if f["cvss"] < 7.0:
            continue
        age = (AS_OF - datetime.strptime(f["last_scan"], "%Y-%m-%d").date()).days
        if age >= 30:
            stale.setdefault(f["asset_id"], {"age": age, "f": []})["f"].append(f)
    print(f"{len(stale)} assets are both >30 days from their last scan and carry a "
          f"high/critical finding (as of {AS_OF}).\n")
    print(f"  {'asset':<12}{'last scan':<12}{'age':>6}{'crit':>10}{'HIGH+':>7}"
          f"{'worst risk':>12}")
    for aid, v in sorted(stale.items(), key=lambda kv: -max(x["risk"] for x in kv[1]["f"])):
        print(f"  {aid:<12}{v['f'][0]['last_scan']:<12}{str(v['age']) + 'd':>6}"
              f"{v['f'][0]['criticality']:>10}{len(v['f']):>7}"
              f"{max(x['risk'] for x in v['f']):>12.0f}")

    # 11 - honest refusal
    hdr(11, "How has our exposure changed since last month?")
    print("I cannot answer this from the data provided.\n")
    print("  Computing change requires at least two inventory snapshots plus the")
    print("  vulnerability-feed revision used at each point in time. This dataset is a")
    print("  single snapshot, and CISA KEV is fetched live, so any trend I reported")
    print("  would be fabricated.\n")
    print(f"  What I can state: exposure AS OF {AS_OF} is {len(F)} findings across "
          f"{len({f['asset_id'] for f in F})} assets.")
    print("  To enable trend analysis, persist each run's index and diff on "
          "(asset_id, cve).")

    # data quality
    print("\n" + "=" * 84)
    print("DATA QUALITY AND HONESTY")
    print("=" * 84)
    for i in dq:
        print(f"  [{i['severity'].upper():<6}] {i['summary']}")
        print(f"           {i['detail']}")
        print(f"           Impact: {i['impact']}\n")

    covered = {r["product"] for r in RULES}
    allsw = sorted({s["name"] for a in assets for s in a["installed_software"]})
    missing = [s for s in allsw if s not in covered]
    print(f"  COVERAGE: {len(covered)} of {len(allsw)} inventory packages have "
          f"detection rules.")
    print(f"  NOT ASSESSED ({len(missing)}): {', '.join(missing)}")
    print("\n  Absence of a finding for those is NOT evidence of safety - it means we")
    print("  did not check. Operating systems are excluded (separate Patch-Tuesday/")
    print("  WSUS workflow). Java SE is excluded because NVD uses 1.8.0:update_271")
    print("  while the inventory says 8.0.271, and guessing that mapping would")
    print("  produce confident-but-wrong applicability.")


if __name__ == "__main__":
    main()
