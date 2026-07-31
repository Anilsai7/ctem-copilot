"""CTEM Exposure Copilot - Streamlit UI.

Run locally:   streamlit run app.py
Deploy:        push to GitHub -> share.streamlit.io -> point at app.py

Data sources: assets.json (provided synthetic inventory) + live CISA KEV catalog.
"""

import io
import json
import os
import ssl
import urllib.request
from datetime import date, datetime

import pandas as pd
import streamlit as st

import solve

ROOT = os.path.dirname(os.path.abspath(__file__))
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

st.set_page_config(page_title="CTEM Exposure Copilot", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

# --------------------------------------------------------------------------
# styling
# --------------------------------------------------------------------------
st.markdown("""
<style>
  .main .block-container {padding-top: 2rem; max-width: 1300px;}
  .metric-row {display:flex; gap:1rem; flex-wrap:wrap;}
  .pill {display:inline-block; padding:2px 9px; border-radius:99px;
         font-size:0.72rem; font-weight:700; letter-spacing:.03em;}
  .crit {background:#B02A37; color:#fff;}
  .high {background:#C4700E; color:#fff;}
  .med  {background:#8A7B1F; color:#fff;}
  .low  {background:#5A6572; color:#fff;}
  .kev  {background:#7B1FA2; color:#fff;}
  .card {border:1px solid rgba(128,140,160,.28); border-radius:10px;
         padding:14px 16px; margin-bottom:10px;}
  .mono {font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
         font-size:.86rem;}
  .muted {color:#7A8696; font-size:.83rem;}
</style>
""", unsafe_allow_html=True)


# --------------------------------------------------------------------------
# data
# --------------------------------------------------------------------------
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


@st.cache_data(ttl=3600, show_spinner=False)
def load_kev():
    """Live CISA KEV, falling back to the bundled snapshot if offline."""
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "ctem-copilot/1.0"})
        with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx()) as r:
            return json.loads(r.read().decode("utf-8")), "live"
    except Exception:
        with open(os.path.join(ROOT, "cache", "kev.json"), encoding="utf-8") as f:
            return json.load(f), "cached"


@st.cache_data(show_spinner=False)
def load_assets():
    with open(os.path.join(ROOT, "data", "assets.json"), encoding="utf-8") as f:
        return json.load(f)


inv = load_assets()
kev_raw, kev_mode = load_kev()
kevidx = {e["cveID"]: e for e in kev_raw["vulnerabilities"]}
F = solve.build_findings(inv, kevidx)
assets = inv["assets"]
AS_OF = solve.AS_OF

df = pd.DataFrame(F)


def band_pill(b):
    cls = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}[b]
    return f'<span class="pill {cls}">{b}</span>'


# --------------------------------------------------------------------------
# sidebar
# --------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### Filters")
    depts = sorted({a["department"] for a in assets})
    types = sorted({a["asset_type"] for a in assets})
    f_dept = st.multiselect("Business unit", depts, default=depts)
    f_type = st.multiselect("Asset type", types, default=types)
    f_kev = st.checkbox("Actively exploited (CISA KEV) only", value=False)
    f_over = st.checkbox("Past CISA deadline only", value=False)
    f_cvss = st.slider("Minimum CVSS", 0.0, 10.0, 0.0, 0.1)

    st.markdown("---")
    st.markdown("### Data sources")
    st.markdown(
        f"<div class='muted'>"
        f"<b>Inventory</b><br/>assets.json — {len(assets)} assets<br/><br/>"
        f"<b>CISA KEV</b> ({kev_mode})<br/>catalog {kev_raw['catalogVersion']}<br/>"
        f"{len(kevidx):,} exploited CVEs<br/>"
        f"released {kev_raw['dateReleased'][:10]}<br/><br/>"
        f"<b>Evaluated as of</b><br/>{AS_OF}</div>",
        unsafe_allow_html=True)

view = [f for f in F
        if f["department"] in f_dept
        and f["asset_type"] in f_type
        and (not f_kev or f["in_kev"])
        and (not f_over or f["overdue"])
        and f["cvss"] >= f_cvss]

# --------------------------------------------------------------------------
# header
# --------------------------------------------------------------------------
st.title("🛡️ CTEM Exposure Copilot")
st.markdown(
    f"<div class='muted'>{inv['metadata']['organisation']} &nbsp;·&nbsp; "
    f"asset inventory cross-referenced against the live CISA Known Exploited "
    f"Vulnerabilities catalog</div>", unsafe_allow_html=True)
st.write("")

c = st.columns(5)
c[0].metric("Assets", len(assets))
c[1].metric("Findings", len(view))
c[2].metric("Actively exploited", sum(1 for f in view if f["in_kev"]))
c[3].metric("Past CISA deadline", sum(1 for f in view if f["overdue"]),
            delta="overdue", delta_color="inverse")
c[4].metric("Assets at risk", len({f["asset_id"] for f in view}))

st.markdown("---")

tab_ask, tab_pri, tab_bu, tab_gaps = st.tabs(
    ["Ask a question", "Remediation priority", "Business units", "Coverage & limits"])

# --------------------------------------------------------------------------
# TAB 1 - ask
# --------------------------------------------------------------------------
with tab_ask:
    QUESTIONS = {
        "Which of our assets have critical unpatched CVEs?": "q1",
        "What is our highest-risk server right now and why?": "q2",
        "Which software package should we patch first?": "q3",
        "How many Finance assets are affected by actively exploited vulnerabilities?": "q4",
        "Are any assets past a CISA KEV due date?": "q5",
        "Summarise our posture for the CISO in 3 sentences": "q6",
        "Which business unit has the most critical exposure?": "q7",
        "What would patching Apache HTTP Server reduce our CVE count by?": "q8",
        "List all CVEs affecting network devices, sorted by CVSS": "q9",
        "Assets not scanned in 30 days that also have high-severity CVEs?": "q10",
    }
    q = st.selectbox("Ask about your exposure", list(QUESTIONS.keys()))
    key = QUESTIONS[q]
    st.write("")

    kevf = [f for f in F if f["in_kev"]]
    od = [f for f in F if f["overdue"]]

    if key == "q1":
        crit = [f for f in F if f["cvss"] >= 9.0]
        st.success(f"**{len({f['asset_id'] for f in crit})} assets** carry a CRITICAL "
                   f"(CVSS ≥ 9.0) vulnerability, across {len(crit)} findings.")
        for f in crit:
            st.markdown(
                f"<div class='card'><span class='mono'><b>{f['asset_id']}</b> "
                f"({f['hostname']})</span> {band_pill(f['band'])} "
                f"{'<span class=pill-kev>' if False else ''}"
                f"<br/><span class='mono'>{f['product']} {f['version']} — "
                f"<b>{f['cve']}</b> CVSS {f['cvss']}</span>"
                f"<br/><span class='muted'>{f['why']}<br/>"
                f"{'CISA due ' + f['due'] + ' — OVERDUE' if f['overdue'] else 'not in KEV'}"
                f" · risk {f['risk']:.0f}/100</span></div>",
                unsafe_allow_html=True)

    elif key == "q2":
        srv = [f for f in F if f["asset_type"] == "server"]
        t = srv[0]
        st.success(f"**{t['asset_id']}** ({t['hostname']}) — {t['department']}, "
                   f"{t['criticality']} criticality — risk {t['risk']:.0f}/100")
        a, b = st.columns([1, 1])
        with a:
            st.markdown("**Why it ranks first**")
            bd = pd.DataFrame([
                {"component": k, "points": v} for k, v in t["breakdown"].items()])
            st.bar_chart(bd.set_index("component"), horizontal=True, height=220)
        with b:
            st.markdown("**Score breakdown**")
            for k, v in t["breakdown"].items():
                st.markdown(f"- `{k}` **+{v}**")
            st.markdown(f"**TOTAL {t['risk']:.0f}/100** {band_pill(t['band'])}",
                        unsafe_allow_html=True)
        st.info(f"**Driver:** {t['cve']} on {t['product']} {t['version']} — {t['why']}")
        same = [f for f in srv if f["asset_id"] == t["asset_id"]][1:]
        if same:
            st.markdown("**Other findings on this host**")
            st.dataframe(pd.DataFrame(same)[
                ["cve", "product", "version", "cvss", "due", "risk"]],
                use_container_width=True, hide_index=True)

    elif key == "q3":
        byp = {}
        for f in F:
            byp.setdefault(f["product"], []).append(f)
        rows = [{
            "package": p,
            "worst action": max(x["risk"] for x in fs),
            "hosts": len({x["asset_id"] for x in fs}),
            "CVEs": len({x["cve"] for x in fs}),
            "KEV": sum(1 for x in fs if x["in_kev"]),
            "overdue": any(x["overdue"] for x in fs),
            "critical hosts": len({x["asset_id"] for x in fs
                                   if x["criticality"] == "critical"}),
        } for p, fs in byp.items()]
        rows.sort(key=lambda r: (-r["worst action"], -r["hosts"]))
        st.success(f"**Patch first: {rows[0]['package']}** — worst single action "
                   f"{rows[0]['worst action']:.0f}/100 across {rows[0]['hosts']} host(s).")
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True,
                     column_config={"worst action": st.column_config.ProgressColumn(
                         "worst action", min_value=0, max_value=100, format="%.0f")})
        st.caption("Ranked by worst single remediation action, not CVE volume — volume "
                   "would put a stale browser above an actively-exploited firewall.")

    elif key == "q4":
        fin = [f for f in F if f["department"] == "Finance" and f["in_kev"]]
        ids = sorted({f["asset_id"] for f in fin})
        tot = len([a for a in assets if a["department"] == "Finance"])
        st.success(f"**{len(ids)} of {tot} Finance assets** — {', '.join(ids)}")
        st.dataframe(pd.DataFrame(fin)[
            ["asset_id", "hostname", "product", "version", "cve", "cvss",
             "due", "overdue", "risk"]], use_container_width=True, hide_index=True)

    elif key == "q5":
        st.error(f"**Yes — {len(od)} findings across "
                 f"{len({f['asset_id'] for f in od})} assets** are past their CISA "
                 f"remediation deadline as of {AS_OF}.")
        r = sorted(od, key=lambda x: x["due"])
        st.dataframe(pd.DataFrame([{
            "asset": f["asset_id"], "CVE": f["cve"], "product": f["product"],
            "version": f["version"], "due": f["due"],
            "days overdue": (AS_OF - datetime.strptime(f["due"], "%Y-%m-%d").date()).days,
            "risk": f["risk"]} for f in r]),
            use_container_width=True, hide_index=True)

    elif key == "q6":
        kassets = {f["asset_id"] for f in kevf}
        crit = {f["asset_id"] for f in kevf if f["criticality"] == "critical"}
        oldest = max((AS_OF - datetime.strptime(f["due"], "%Y-%m-%d").date()).days
                     for f in od)
        st.markdown(f"""
> **1.** Across **{len(assets)} assets** we confirmed **{len(F)} findings** covering
> **{len({f['cve'] for f in F})} distinct CVEs**, of which
> **{len({f['cve'] for f in kevf})}** are on CISA's Known Exploited Vulnerabilities
> list and are therefore under active attack in the wild.
>
> **2.** **{len(kassets)} assets** carry at least one actively-exploited CVE —
> **{len(crit)} of them business-critical** — and **{len(od)} findings** are already
> past their federal remediation deadline, the oldest by **{oldest:,} days**.
>
> **3.** The single highest-risk item is **{F[0]['cve']}** on **{F[0]['asset_id']}**
> ({F[0]['product']} {F[0]['version']}, risk {F[0]['risk']:.0f}/100); this analysis
> covers {len({r[0] for r in solve.RULES})} high-signal packages and excludes
> operating-system patching, so it is a **floor** on exposure, not a complete picture.
""")

    elif key == "q7":
        byd = {}
        for f in F:
            byd.setdefault(f["department"], []).append(f)
        dtot = {}
        for a in assets:
            dtot[a["department"]] = dtot.get(a["department"], 0) + 1
        rows = [{
            "unit": d, "worst finding": max(x["risk"] for x in fs),
            "findings": len(fs), "KEV": sum(1 for x in fs if x["in_kev"]),
            "overdue": sum(1 for x in fs if x["overdue"]),
            "assets hit": f"{len({x['asset_id'] for x in fs})}/{dtot[d]}",
            "critical assets": len({x["asset_id"] for x in fs
                                    if x["criticality"] == "critical"}),
        } for d, fs in byd.items()]
        rows.sort(key=lambda r: (-r["worst finding"], -r["KEV"]))
        st.success(f"**{rows[0]['unit']}** — worst single finding "
                   f"{rows[0]['worst finding']:.0f}/100.")
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True,
                     column_config={"worst finding": st.column_config.ProgressColumn(
                         "worst finding", min_value=0, max_value=100, format="%.0f")})
        st.caption("Ranked by worst single finding, so a large unit cannot win on "
                   "headcount alone.")

    elif key == "q8":
        ap = [f for f in F if f["product"] == "Apache HTTP Server"]
        rest = {f["cve"] for f in F if f["product"] != "Apache HTTP Server"}
        before = len({f["cve"] for f in F})
        m = st.columns(4)
        m[0].metric("Hosts affected", len({f["asset_id"] for f in ap}))
        m[1].metric("CVEs closed", len({f["cve"] for f in ap}))
        m[2].metric("Fleet CVEs", f"{before} → {len(rest)}", delta=-(before - len(rest)))
        m[3].metric("Actively exploited closed",
                    len({f["cve"] for f in ap if f["in_kev"]}))
        st.dataframe(pd.DataFrame(ap)[
            ["asset_id", "hostname", "version", "cve", "cvss", "due", "risk"]],
            use_container_width=True, hide_index=True)
        st.info("One action — *upgrade Apache to 2.4.58+ on FIN-SRV-001* — closes both.")

    elif key == "q9":
        nd = sorted([f for f in F if f["asset_type"] == "network_device"],
                    key=lambda x: -x["cvss"])
        st.success(f"**{len(nd)} CVEs** across "
                   f"{len({f['asset_id'] for f in nd})} network devices.")
        for f in nd:
            st.markdown(
                f"<div class='card'><span class='mono'><b>{f['cve']}</b> — "
                f"CVSS {f['cvss']}</span> {band_pill(f['band'])}<br/>"
                f"<span class='mono'>{f['asset_id']} ({f['hostname']}) — "
                f"{f['product']} {f['version']}</span><br/>"
                f"<span class='muted'>{f['why']}<br/>CISA due {f['due']} "
                f"{'— OVERDUE' if f['overdue'] else ''} · risk {f['risk']:.0f}/100"
                f"</span></div>", unsafe_allow_html=True)

    elif key == "q10":
        stale = {}
        for f in F:
            if f["cvss"] < 7.0:
                continue
            age = (AS_OF - datetime.strptime(f["last_scan"], "%Y-%m-%d").date()).days
            if age >= 30:
                stale.setdefault(f["asset_id"], {"age": age, "f": []})["f"].append(f)
        st.warning(f"**{len(stale)} assets.** Every asset in this inventory was last "
                   f"scanned in early-to-mid 2026, so as of {AS_OF} the entire fleet "
                   f"is stale — that is itself the finding.")
        st.dataframe(pd.DataFrame([{
            "asset": k, "last scan": v["f"][0]["last_scan"],
            "days since scan": v["age"], "criticality": v["f"][0]["criticality"],
            "HIGH+ CVEs": len(v["f"]),
            "worst risk": max(x["risk"] for x in v["f"])}
            for k, v in sorted(stale.items(),
                               key=lambda kv: -max(x["risk"] for x in kv[1]["f"]))]),
            use_container_width=True, hide_index=True)

# --------------------------------------------------------------------------
# TAB 2 - priority queue
# --------------------------------------------------------------------------
with tab_pri:
    st.markdown("#### Monday-morning remediation queue")
    st.caption("Ranked by risk score. Every row is one patch action with its full "
               "evidence trail — asset, product, CVE, CVSS, KEV status, CISA deadline.")
    if not view:
        st.info("No findings match the current filters.")
    else:
        st.dataframe(pd.DataFrame([{
            "risk": f["risk"], "band": f["band"], "asset": f["asset_id"],
            "hostname": f["hostname"], "unit": f["department"],
            "criticality": f["criticality"], "product": f["product"],
            "version": f["version"], "CVE": f["cve"], "CVSS": f["cvss"],
            "KEV": "yes" if f["in_kev"] else "no",
            "ransomware": "yes" if f["ransomware"] else "",
            "CISA due": f["due"] or "", "overdue": "OVERDUE" if f["overdue"] else "",
        } for f in view]), use_container_width=True, hide_index=True, height=520,
            column_config={"risk": st.column_config.ProgressColumn(
                "risk", min_value=0, max_value=100, format="%.0f")})

        st.download_button(
            "Download queue as CSV",
            pd.DataFrame(view).to_csv(index=False).encode(),
            file_name="remediation_queue.csv", mime="text/csv")

        with st.expander("Show scoring model"):
            st.markdown("""
| Component | Max | Rationale |
|---|---:|---|
| CVSS severity | 30 | Capped — CVSS alone produced the client's unusable 3,400-item list |
| Exploitation (CISA KEV) | 30 | Weighted equal to severity: a 7.5 under active attack beats a theoretical 9.8 |
| Asset criticality | 25 | Business impact of the host |
| Deadline urgency | 15 | CISA due date proximity / overdue |

**Known gap:** network exposure (internet-facing vs internal) is one of the strongest
real prioritisation signals and is absent from the inventory, so it contributes nothing.
""")

# --------------------------------------------------------------------------
# TAB 3 - business units
# --------------------------------------------------------------------------
with tab_bu:
    byd, dtot = {}, {}
    for f in F:
        byd.setdefault(f["department"], []).append(f)
    for a in assets:
        dtot[a["department"]] = dtot.get(a["department"], 0) + 1
    rows = [{
        "unit": d, "worst finding": max(x["risk"] for x in fs), "findings": len(fs),
        "KEV findings": sum(1 for x in fs if x["in_kev"]),
        "overdue": sum(1 for x in fs if x["overdue"]),
        "assets affected": len({x["asset_id"] for x in fs}),
        "assets total": dtot[d],
        "critical assets hit": len({x["asset_id"] for x in fs
                                    if x["criticality"] == "critical"}),
    } for d, fs in byd.items()]
    rows.sort(key=lambda r: -r["worst finding"])
    a, b = st.columns([3, 2])
    with a:
        st.markdown("#### Exposure by business unit")
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True,
                     column_config={"worst finding": st.column_config.ProgressColumn(
                         "worst finding", min_value=0, max_value=100, format="%.0f")})
    with b:
        st.markdown("#### Actively-exploited findings")
        st.bar_chart(pd.DataFrame(rows).set_index("unit")[["KEV findings"]], height=300)

    st.markdown("#### Every asset")
    arows = []
    for a_ in assets:
        af = [f for f in F if f["asset_id"] == a_["asset_id"]]
        arows.append({
            "asset": a_["asset_id"], "hostname": a_["hostname"],
            "unit": a_["department"], "type": a_["asset_type"],
            "criticality": a_["criticality"], "last scan": a_["last_scan_date"],
            "findings": len(af), "KEV": sum(1 for x in af if x["in_kev"]),
            "worst risk": max([x["risk"] for x in af], default=0),
        })
    arows.sort(key=lambda r: -r["worst risk"])
    st.dataframe(pd.DataFrame(arows), use_container_width=True, hide_index=True)

# --------------------------------------------------------------------------
# TAB 4 - coverage
# --------------------------------------------------------------------------
with tab_gaps:
    covered = {r[0] for r in solve.RULES}
    allsw = sorted({s["name"] for a in assets for s in a["installed_software"]})
    missing = [s for s in allsw if s not in covered]
    st.markdown("#### What this analysis does **not** cover")
    st.error("Absence of a finding here is **not** evidence of safety. It means we "
             "did not check. Conflating those two is how vulnerability programmes "
             "lose credibility.")
    m = st.columns(3)
    m[0].metric("Packages with rules", len(covered))
    m[1].metric("Packages in inventory", len(allsw))
    m[2].metric("Not assessed", len(missing))
    st.dataframe(pd.DataFrame({"package (not assessed)": missing}),
                 use_container_width=True, hide_index=True, height=300)

    st.markdown("""
#### Deliberate scope decisions

**Operating systems are excluded.** Querying every Windows/RHEL CVE returns hundreds of
results and recreates the 3,400-finding noise problem this tool exists to fix. OS
patching also runs on a separate workflow (Patch Tuesday → WSUS/MECM/Satellite) with
its own owners and cadence.

**Java SE is excluded.** NVD identifies it as `1.8.0:update_271`; the inventory says
`8.0.271`. Reconciling those by guesswork produces confident-but-wrong applicability,
so it is flagged for manual review instead.

**Why KEV-scoped rather than full-NVD.** Querying NVD by CPE returns every CVE fixed in
any *later* release — a browser 40 versions behind yields ~2,300 technically-applicable
CVEs. Technically correct, operationally useless. 22 precise findings beat 14,080 true
ones nobody reads.

#### Where this can still fail

1. **Version rules are hand-curated** — a wrong rule produces a confidently wrong finding.
2. **Inventory accuracy is assumed** — if the CMDB says 2.4.49 and the host runs 2.4.58,
   every downstream conclusion is wrong. Production needs authenticated scan data.
3. **No EPSS** — exploit-prediction scoring would materially improve ranking of non-KEV findings.
4. **No attack-path context** — "this workstation is one hop from the DC" doesn't affect ranking yet.
""")

st.markdown("---")
st.caption(f"Sources: assets.json · CISA KEV {kev_raw['catalogVersion']} "
           f"({kev_mode}, {len(kevidx):,} exploited CVEs, released "
           f"{kev_raw['dateReleased'][:10]}) · evaluated as of {AS_OF}")
