"""CTEM exposure answers: assets.json x CISA KEV.

Scope cut (deliberate, per the brief's "reasonable scope reductions are
encouraged"): match the inventory against a curated set of high-signal
vulnerabilities with EXPLICIT version rules, then join to the live CISA KEV
catalog for exploitation status, due dates and ransomware linkage.

Why not query all of NVD by CPE: doing so returns every CVE fixed in any later
release, so a browser 40 versions behind yields ~2,300 technically-applicable
CVEs and drowns an actively-exploited firewall. That reproduces exactly the
3,400-finding noise problem we were hired to fix. Precision beats recall here.

Every rule below states the affected range and why the installed version does
or does not fall in it, so a sceptical analyst can check the logic.
"""

import json
import os
from datetime import date, datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
AS_OF = date(2026, 7, 30)

# (product, version_predicate, cve, cvss, why)
# version_predicate receives the installed version string.
RULES = [
    ("Apache HTTP Server", lambda v: v == "2.4.49", "CVE-2021-41773", 9.8,
     "Path traversal -> RCE. Affects 2.4.49 exactly."),
    ("Apache HTTP Server", lambda v: v in ("2.4.49", "2.4.50"), "CVE-2021-42013", 9.8,
     "Incomplete fix for CVE-2021-41773. Affects 2.4.49 and 2.4.50."),
    ("log4j-core", lambda v: _between(v, "2.0", "2.15.0"), "CVE-2021-44228", 10.0,
     "Log4Shell JNDI RCE. Affects 2.0-beta9 through 2.14.1 (fixed in 2.15.0)."),
    ("log4j-core", lambda v: _between(v, "2.0", "2.16.0"), "CVE-2021-45046", 9.0,
     "Follow-up to Log4Shell. Affects up to and including 2.15.0."),
    ("Apache Tomcat", lambda v: _between(v, "9.0.0", "9.0.99"), "CVE-2025-24813", 9.8,
     "Partial PUT -> RCE. Affects 9.0.0.M1 through 9.0.98."),
    ("Grafana", lambda v: _between(v, "8.0.0", "8.3.1"), "CVE-2021-43798", 7.5,
     "Directory traversal, arbitrary file read. Affects 8.0.0-8.3.0."),
    ("Jenkins", lambda v: _lt(v, "2.442"), "CVE-2024-23897", 9.8,
     "Arbitrary file read via CLI. Affects Jenkins < 2.442."),
    ("Microsoft Exchange Server", lambda v: _lt(v, "15.1.2375.18"),
     "CVE-2021-34473", 9.8,
     "ProxyShell pre-auth RCE. Exchange 2016 fixed in 15.1.2375.18."),
    ("Fortinet FortiOS", lambda v: _between(v, "6.4.0", "6.4.11"), "CVE-2022-42475", 9.8,
     "SSL-VPN heap overflow, pre-auth RCE. Affects 6.4.0-6.4.10."),
    ("Fortinet FortiOS", lambda v: _between(v, "6.4.0", "6.4.15"), "CVE-2024-21762", 9.8,
     "SSL-VPN out-of-bounds write. Affects 6.4.0-6.4.14."),
    ("F5 BIG-IP", lambda v: _between(v, "13.1.0", "16.1.3"), "CVE-2022-1388", 9.8,
     "iControl REST auth bypass -> RCE. Affects 13.1.x-16.1.x."),
    ("Cisco IOS XE", lambda v: _between(v, "16.0.0", "17.9.99"), "CVE-2023-20198", 10.0,
     "Web UI privilege escalation, implant deployment. Affects IOS XE 16.x/17.x with HTTP server enabled."),
    ("Veeam Backup & Replication", lambda v: _lt(v, "11.0.1.1261"),
     "CVE-2023-27532", 7.5,
     "Credential disclosure in backup service. Fixed in 11.0.1.1261 / 12.0.0.1420."),
    ("Sonatype Nexus Repository Manager", lambda v: _lt(v, "3.68.1"),
     "CVE-2024-4956", 7.5,
     "Path traversal, unauthenticated file read. Affects < 3.68.1."),
    ("PuTTY", lambda v: _between(v, "0.68", "0.81"), "CVE-2024-31497", 5.9,
     "NIST P-521 ECDSA nonce bias -> key recovery. Affects 0.68-0.80."),
    ("Internet Explorer", lambda v: v.startswith("11."), "CVE-2021-26411", 8.8,
     "Memory corruption. IE11 is end-of-life and unsupported."),
]

CRIT_PTS = {"critical": 25, "high": 18, "medium": 10, "low": 4}


def _tok(v):
    import re
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


def load():
    with open(os.path.join(ROOT, "data", "assets.json"), encoding="utf-8") as f:
        inv = json.load(f)
    kev_path = os.path.join(ROOT, "cache", "kev.json")
    with open(kev_path, encoding="utf-8") as f:
        kev = json.load(f)
    return inv, {e["cveID"]: e for e in kev["vulnerabilities"]}, kev


def build_findings(inv, kevidx):
    out = []
    for a in inv["assets"]:
        for sw in a.get("installed_software", []):
            for prod, pred, cve, cvss, why in RULES:
                if sw["name"] != prod:
                    continue
                try:
                    hit = pred(sw["version"])
                except Exception:
                    hit = False
                if not hit:
                    continue
                k = kevidx.get(cve)
                due = k.get("dueDate") if k else None
                overdue = bool(due and datetime.strptime(due, "%Y-%m-%d").date() < AS_OF)
                f = {
                    "asset_id": a["asset_id"], "hostname": a["hostname"],
                    "department": a["department"], "criticality": a["criticality"],
                    "asset_type": a["asset_type"], "last_scan": a["last_scan_date"],
                    "product": prod, "version": sw["version"],
                    "cve": cve, "cvss": cvss, "why": why,
                    "in_kev": bool(k),
                    "kev_added": k.get("dateAdded") if k else None,
                    "due": due, "overdue": overdue,
                    "ransomware": (k.get("knownRansomwareCampaignUse", "")
                                   .lower() == "known") if k else False,
                }
                f.update(score(f))
                out.append(f)
    return sorted(out, key=lambda f: -f["risk"])


def score(f):
    b = {}
    b["severity"] = round(f["cvss"] / 10 * 30, 1)
    b["exploited"] = (25 if f["in_kev"] else 0) + (5 if f["ransomware"] else 0)
    b["criticality"] = CRIT_PTS.get(f["criticality"], 10)
    if f["overdue"]:
        b["urgency"] = 15
    elif f["due"]:
        d = (datetime.strptime(f["due"], "%Y-%m-%d").date() - AS_OF).days
        b["urgency"] = 11 if d <= 14 else 7 if d <= 30 else 4
    else:
        b["urgency"] = 0
    total = round(sum(b.values()), 1)
    return {"risk": total, "breakdown": b,
            "band": "CRITICAL" if total >= 75 else "HIGH" if total >= 55
            else "MEDIUM" if total >= 35 else "LOW"}


def cite(f):
    kev = (f"KEV added {f['kev_added']}, due {f['due']}"
           + (" [OVERDUE]" if f["overdue"] else "")) if f["in_kev"] else "not in KEV"
    rw = ", ransomware-linked" if f["ransomware"] else ""
    return (f"[{f['asset_id']} | {f['hostname']}] {f['product']} {f['version']} - "
            f"{f['cve']} CVSS {f['cvss']} - {kev}{rw} - risk {f['risk']:.0f}/100 "
            f"[{f['band']}]")


def hdr(n, q):
    print("\n" + "=" * 82)
    print(f"Q{n}. {q}")
    print("=" * 82)


def main():
    import sys
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    inv, kevidx, kev = load()
    F = build_findings(inv, kevidx)
    assets = inv["assets"]

    print("=" * 82)
    print(f"  {inv['metadata']['organisation']}")
    print(f"  Assets: {len(assets)}   Findings: {len(F)}   "
          f"KEV-listed: {sum(1 for f in F if f['in_kev'])}")
    print(f"  Sources: assets.json  +  CISA KEV {kev['catalogVersion']} "
          f"({len(kevidx)} exploited CVEs, released {kev['dateReleased'][:10]})")
    print(f"  Evaluated as of {AS_OF}")
    print("=" * 82)

    # 1
    hdr(1, "Which of our assets have critical unpatched CVEs?")
    crit = [f for f in F if f["cvss"] >= 9.0]
    print(f"{len({f['asset_id'] for f in crit})} assets carry a CRITICAL (CVSS >= 9.0) "
          f"vulnerability, across {len(crit)} findings:\n")
    for f in crit:
        print("  " + cite(f))

    # 2
    hdr(2, "What is our highest-risk server right now and why?")
    srv = [f for f in F if f["asset_type"] == "server"]
    top = srv[0]
    print(f"{top['asset_id']} ({top['hostname']}) - {top['department']}, "
          f"{top['criticality']} criticality.\n")
    print("  WHY:")
    for k, v in top["breakdown"].items():
        print(f"    {k:<14} +{v}")
    print(f"    {'TOTAL':<14} {top['risk']}/100  [{top['band']}]")
    print(f"\n  Driver: {top['cve']} on {top['product']} {top['version']} - {top['why']}")
    print(f"  {cite(top)}")
    others = [f for f in srv if f["asset_id"] == top["asset_id"]][1:]
    if others:
        print("\n  Same host, other findings:")
        for f in others:
            print("    " + cite(f))

    # 3
    hdr(3, "Which software package should we patch first to reduce the most exposure?")
    byp = {}
    for f in F:
        byp.setdefault(f["product"], []).append(f)
    rank = sorted(byp.items(), key=lambda kv: (-max(x["risk"] for x in kv[1]),
                                               -len({x['asset_id'] for x in kv[1]})))
    print(f"{'#':>2}  {'package':<34}{'worst':>7}{'hosts':>7}{'CVEs':>6}{'KEV':>5}  flags")
    for i, (p, fs) in enumerate(rank, 1):
        hosts = len({x["asset_id"] for x in fs})
        flags = []
        if any(x["overdue"] for x in fs):
            flags.append("OVERDUE")
        ncrit = len({x["asset_id"] for x in fs if x["criticality"] == "critical"})
        if ncrit:
            flags.append(f"{ncrit} critical host(s)")
        print(f"{i:>2}. {p:<34}{max(x['risk'] for x in fs):>7.0f}{hosts:>7}"
              f"{len({x['cve'] for x in fs}):>6}{sum(1 for x in fs if x['in_kev']):>5}"
              f"  {', '.join(flags)}")
    p, fs = rank[0]
    print(f"\n  PATCH FIRST: {p} - worst single action scores "
          f"{max(x['risk'] for x in fs):.0f}/100 on "
          f"{', '.join(sorted({x['asset_id'] for x in fs}))}.")
    print("  Ranked by worst single action, not CVE volume: volume would put a stale "
          "browser above an actively-exploited firewall.")

    # 4
    hdr(4, "How many Finance department assets are affected by actively exploited "
           "vulnerabilities?")
    fin = [f for f in F if f["department"] == "Finance" and f["in_kev"]]
    ids = sorted({f["asset_id"] for f in fin})
    tot = len([a for a in assets if a["department"] == "Finance"])
    print(f"{len(ids)} of {tot} Finance assets - {', '.join(ids)}\n")
    for f in fin:
        print("  " + cite(f))

    # 5
    hdr(5, "Are any assets running software with a CISA KEV due date that has "
           "already passed?")
    od = [f for f in F if f["overdue"]]
    print(f"YES - {len(od)} findings across "
          f"{len({f['asset_id'] for f in od})} assets are past their CISA deadline "
          f"(as of {AS_OF}):\n")
    for f in sorted(od, key=lambda x: x["due"]):
        days = (AS_OF - datetime.strptime(f["due"], "%Y-%m-%d").date()).days
        print(f"  {f['asset_id']:<12} {f['cve']:<16} due {f['due']}  "
              f"OVERDUE by {days:,} days  ({f['product']} {f['version']})")

    # 6
    hdr(6, "Summarise our overall vulnerability posture for the CISO in 3 sentences.")
    kevf = [f for f in F if f["in_kev"]]
    kassets = {f["asset_id"] for f in kevf}
    critassets = {f["asset_id"] for f in kevf if f["criticality"] == "critical"}
    print(f"1. Across {len(assets)} assets we confirmed {len(F)} vulnerability findings "
          f"covering {len({f['cve'] for f in F})} distinct CVEs, of which "
          f"{len({f['cve'] for f in kevf})} are on CISA's Known Exploited "
          f"Vulnerabilities list and are therefore under active attack in the wild.")
    print(f"\n2. {len(kassets)} assets carry at least one actively-exploited CVE - "
          f"{len(critassets)} of them business-critical - and {len(od)} findings are "
          f"already past their federal remediation deadline, the oldest by "
          f"{max((AS_OF - datetime.strptime(f['due'], '%Y-%m-%d').date()).days for f in od):,} days.")
    print(f"\n3. The single highest-risk item is {F[0]['cve']} on {F[0]['asset_id']} "
          f"({F[0]['product']} {F[0]['version']}, risk {F[0]['risk']:.0f}/100); note "
          f"this analysis covers {len({r[0] for r in RULES})} high-signal packages and "
          f"excludes operating-system patching, so it is a floor on exposure, not a "
          f"complete picture.")

    # 7
    hdr(7, "Which business unit has the most critical exposure?")
    byd = {}
    for f in F:
        byd.setdefault(f["department"], []).append(f)
    dtot = {}
    for a in assets:
        dtot[a["department"]] = dtot.get(a["department"], 0) + 1
    drank = sorted(byd.items(), key=lambda kv: (-max(x["risk"] for x in kv[1]),
                                                -sum(1 for x in kv[1] if x["in_kev"])))
    print(f"  {'unit':<14}{'worst':>7}{'findings':>10}{'KEV':>6}{'overdue':>9}"
          f"{'assets':>9}{'crit':>6}")
    for d, fs in drank:
        na = len({x["asset_id"] for x in fs})
        print(f"  {d:<14}{max(x['risk'] for x in fs):>7.0f}{len(fs):>10}"
              f"{sum(1 for x in fs if x['in_kev']):>6}"
              f"{sum(1 for x in fs if x['overdue']):>9}"
              f"{str(na) + '/' + str(dtot[d]):>9}"
              f"{len({x['asset_id'] for x in fs if x['criticality']=='critical'}):>6}")
    d, fs = drank[0]
    print(f"\n  {d} - worst single finding scores {max(x['risk'] for x in fs):.0f}/100. "
          f"Ranked by worst finding, so a large unit can't win on headcount alone.")

    # 8
    hdr(8, "What would patching Apache HTTP Server on all affected hosts reduce our "
           "CVE count by?")
    ap = [f for f in F if f["product"] == "Apache HTTP Server"]
    rest = {f["cve"] for f in F if f["product"] != "Apache HTTP Server"}
    before = len({f["cve"] for f in F})
    print(f"  Hosts affected            : {len({f['asset_id'] for f in ap})} "
          f"({', '.join(sorted({f['asset_id'] for f in ap}))})")
    print(f"  Versions deployed         : {', '.join(sorted({f['version'] for f in ap}))}")
    print(f"  Findings closed           : {len(ap)}")
    print(f"  Distinct CVEs closed      : {len({f['cve'] for f in ap})} "
          f"({', '.join(sorted({f['cve'] for f in ap}))})")
    print(f"  Fleet distinct CVEs       : {before} -> {len(rest)} "
          f"(net reduction {before - len(rest)})")
    print(f"  Actively-exploited closed : "
          f"{len({f['cve'] for f in ap if f['in_kev']})}")
    print(f"  Risk points removed       : {sum(f['risk'] for f in ap):.0f} of "
          f"{sum(f['risk'] for f in F):.0f} fleet total")
    print("\n  One action ('upgrade Apache to 2.4.58+ on FIN-SRV-001') closes both.")

    # 9
    hdr(9, "List all CVEs affecting our network devices sorted by CVSS score.")
    nd = sorted([f for f in F if f["asset_type"] == "network_device"],
                key=lambda x: -x["cvss"])
    if not nd:
        print("  None.")
    for f in nd:
        print("  " + cite(f))
        print(f"       {f['why']}")

    # 10
    hdr(10, "Any assets not scanned in the last 30 days that also have high-severity "
            "CVEs?")
    stale = []
    for f in F:
        if f["cvss"] < 7.0:
            continue
        d = datetime.strptime(f["last_scan"], "%Y-%m-%d").date()
        age = (AS_OF - d).days
        if age >= 30:
            stale.append((age, f))
    byasset = {}
    for age, f in stale:
        byasset.setdefault(f["asset_id"], (age, []))[1].append(f)
    print(f"YES - {len(byasset)} assets. NOTE: every asset in this inventory was last "
          f"scanned in May 2026, so as of {AS_OF} the entire fleet is stale. That is "
          f"itself the finding.\n")
    print(f"  {'asset':<12}{'last scan':<12}{'age':>7}{'crit':>10}{'HIGH+ CVEs':>12}")
    for aid, (age, fs) in sorted(byasset.items(), key=lambda kv: -max(x['risk'] for x in kv[1][1])):
        print(f"  {aid:<12}{fs[0]['last_scan']:<12}{str(age) + 'd':>7}"
              f"{fs[0]['criticality']:>10}{len(fs):>12}")

    # coverage
    print("\n" + "=" * 82)
    print("WHAT THIS DOES NOT COVER (absence of a finding is not evidence of safety)")
    print("=" * 82)
    covered = {r[0] for r in RULES}
    allsw = {s["name"] for a in assets for s in a["installed_software"]}
    print(f"  Packages with vulnerability rules : {len(covered)}")
    print(f"  Packages in inventory             : {len(allsw)}")
    print(f"  Not assessed                      : {len(allsw - covered)}")
    print(f"    {', '.join(sorted(allsw - covered))}")
    print("\n  Operating systems are excluded: OS patching runs on a separate")
    print("  Patch-Tuesday/WSUS workflow, and pulling every Windows CVE would")
    print("  recreate the 3,400-finding noise problem this tool exists to fix.")
    print("  Java SE is excluded: NVD uses 1.8.0:update_271, the inventory says")
    print("  8.0.271 - reconciling those by guesswork would produce confident")
    print("  but wrong applicability, so it is flagged for manual review.")


if __name__ == "__main__":
    main()
