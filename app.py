"""CTEM Exposure Copilot - Streamlit UI.

Run locally:   streamlit run app.py
Deploy:        push to GitHub -> share.streamlit.io -> main file app.py

Data: assets.json (provided inventory) + live CISA KEV catalog.
"""

import json
from datetime import datetime

import pandas as pd
import streamlit as st

import llm_layer
import solve

st.set_page_config(page_title="CTEM Exposure Copilot", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
  .main .block-container {padding-top:2rem; max-width:1320px;}
  .pill {display:inline-block; padding:2px 9px; border-radius:99px;
         font-size:.70rem; font-weight:700; letter-spacing:.03em;}
  .crit{background:#B02A37;color:#fff}.high{background:#C4700E;color:#fff}
  .med{background:#8A7B1F;color:#fff}.low{background:#5A6572;color:#fff}
  .cf{background:#1B6E4A;color:#fff}.lk{background:#B5730F;color:#fff}
  .un{background:#6B4E9E;color:#fff}
  .card{border:1px solid rgba(128,140,160,.28);border-radius:10px;
        padding:13px 16px;margin-bottom:9px}
  .mono{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:.85rem}
  .muted{color:#7A8696;font-size:.82rem}
  .cav{color:#8a4b00;background:rgba(197,138,0,.10);padding:8px 10px;
       border-radius:7px;font-size:.80rem;margin-top:7px}
</style>""", unsafe_allow_html=True)


# --------------------------------------------------------------------------
@st.cache_data(ttl=3600, show_spinner=False)
def get_kev():
    return solve.load_kev()


@st.cache_data(show_spinner=False)
def get_assets():
    return solve.load_assets()


inv = get_assets()
kev_raw, kev_mode = get_kev()
kevidx = {e["cveID"]: e for e in kev_raw["vulnerabilities"]}
AS_OF = solve.analysis_date(inv)
F = solve.build_findings(inv, kevidx, AS_OF)
DQ = solve.data_quality(inv)
assets = inv["assets"]

CONF = {"confirmed": "cf", "likely": "lk", "uncertain": "un"}


def pill(text, cls):
    return f'<span class="pill {cls}">{text}</span>'


def band_pill(b):
    return pill(b, {"CRITICAL": "crit", "HIGH": "high",
                    "MEDIUM": "med", "LOW": "low"}[b])


def conf_pill(c):
    return pill(c.upper(), CONF[c])


def finding_card(f):
    cav = f'<div class="cav"><b>Needs verification:</b> {f["caveat"]}</div>' \
        if f["caveat"] else ""
    kev = (f'KEV added {f["kev_added"]} · CISA due {f["due"]}'
           + (' · <b>OVERDUE</b>' if f["overdue"] else '')) if f["in_kev"] \
        else 'not in CISA KEV'
    rw = ' · ransomware-linked' if f["ransomware"] else ''
    return (f'<div class="card"><span class="mono"><b>{f["asset_id"]}</b> '
            f'({f["hostname"]})</span> {band_pill(f["band"])} {conf_pill(f["confidence"])}'
            f'<br/><span class="mono">{f["product"]} {f["version"]} — '
            f'<a href="{f["nvd_url"]}" target="_blank"><b>{f["cve"]}</b></a> '
            f'CVSS {f["cvss"]}</span>'
            f'<br/><span class="muted">{f["why"]}<br/>{kev}{rw} · '
            f'risk {f["risk"]:.0f}/100</span>{cav}</div>')


# --------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### Filters")
    depts = sorted({a["department"] for a in assets})
    types = sorted({a["asset_type"] for a in assets})
    f_dept = st.multiselect("Business unit", depts, default=depts)
    f_type = st.multiselect("Asset type", types, default=types)
    f_conf = st.multiselect("Confidence", ["confirmed", "likely", "uncertain"],
                            default=["confirmed", "likely", "uncertain"])
    f_kev = st.checkbox("Actively exploited (CISA KEV) only")
    f_over = st.checkbox("Past CISA deadline only")
    f_cvss = st.slider("Minimum CVSS", 0.0, 10.0, 0.0, 0.1)

    st.markdown("---")
    st.markdown("### AI narration")
    llm_ok, llm_msg = llm_layer.status()
    use_llm = st.toggle("Use Claude to write answers", value=False,
                        disabled=not llm_ok,
                        help="Claude narrates the findings the engine already "
                             "computed. It never calculates or looks anything up.")
    if llm_ok:
        st.caption(f"🟢 {llm_msg}")
    else:
        st.caption(f"⚪ Deterministic mode — {llm_msg}")
    st.caption("Every generated answer is checked by a non-LLM verifier before "
               "display. See the **How AI is used** tab.")

    st.markdown("---")
    st.markdown("### Sources")
    st.markdown(
        f"<div class='muted'><b>Inventory</b><br/>assets.json — {len(assets)} assets"
        f"<br/><br/><b>CISA KEV</b> ({kev_mode})<br/>catalog "
        f"{kev_raw['catalogVersion']}<br/>{len(kevidx):,} exploited CVEs<br/>"
        f"released {kev_raw['dateReleased'][:10]}<br/><br/>"
        f"<b>Analysis date</b><br/>{AS_OF}<br/>"
        f"<i>newest scan in the dataset, not wall-clock — keeps the report "
        f"reproducible</i></div>", unsafe_allow_html=True)

view = [f for f in F
        if f["department"] in f_dept and f["asset_type"] in f_type
        and f["confidence"] in f_conf
        and (not f_kev or f["in_kev"]) and (not f_over or f["overdue"])
        and f["cvss"] >= f_cvss]

conf = [f for f in F if f["confidence"] == "confirmed"]
likely = [f for f in F if f["confidence"] == "likely"]
unc = [f for f in F if f["confidence"] == "uncertain"]
od = [f for f in F if f["overdue"]]
kevf = [f for f in F if f["in_kev"]]

# --------------------------------------------------------------------------
st.title("🛡️ CTEM Exposure Copilot")
st.markdown(f"<div class='muted'>{inv['metadata']['organisation']} &nbsp;·&nbsp; "
            f"asset inventory cross-referenced against the live CISA Known Exploited "
            f"Vulnerabilities catalog</div>", unsafe_allow_html=True)
st.write("")

c = st.columns(6)
c[0].metric("Assets", len(assets))
c[1].metric("Findings", len(view))
c[2].metric("Confirmed", len([f for f in view if f["confidence"] == "confirmed"]))
c[3].metric("Needs verification",
            len([f for f in view if f["confidence"] != "confirmed"]))
c[4].metric("Actively exploited", len([f for f in view if f["in_kev"]]))
c[5].metric("Past deadline", len([f for f in view if f["overdue"]]),
            delta="overdue", delta_color="inverse")

st.markdown("---")
t_ask, t_q, t_bu, t_dq, t_ai = st.tabs(
    ["Ask a question", "Remediation queue", "Business units",
     "Data quality & limits", "How AI is used"])

# ============================ ASK =========================================
QMAP = {
    "critical": "Which of our assets have critical unpatched CVEs?",
    "top_asset": "What is our highest-risk server right now and why?",
    "patch_first": "Which software package should we patch first?",
    "finance_kev": "How many Finance assets are affected by actively exploited "
                   "vulnerabilities?",
    "overdue": "Are any assets past a CISA KEV due date?",
    "ciso": "Summarise our posture for the CISO in 3 sentences",
    "unit": "Which business unit has the most critical exposure?",
    "apache": "What would patching Apache HTTP Server reduce our CVE count by?",
    "network": "List all CVEs affecting network devices, sorted by CVSS",
    "stale": "Assets not scanned in 30 days that also have high-severity CVEs?",
    "trend": "How has our exposure changed since last month?",
    "coverage": "What did you NOT assess?",
}
ORDER = list(QMAP.keys())


def findings_for(key):
    """The evidence subset an LLM narration for this intent may reference."""
    if key == "critical":
        return [f for f in F if f["cvss"] >= 9.0]
    if key == "top_asset":
        srv = [f for f in F if f["asset_type"] == "server"]
        return [f for f in srv if f["asset_id"] == srv[0]["asset_id"]] if srv else []
    if key == "finance_kev":
        return [f for f in F if f["department"] == "Finance" and f["in_kev"]]
    if key == "overdue":
        return [f for f in F if f["overdue"]]
    if key == "apache":
        return [f for f in F if f["product"] == "Apache HTTP Server"]
    if key == "network":
        return [f for f in F if f["asset_type"] == "network_device"]
    if key == "stale":
        return [f for f in F if f["cvss"] >= 7.0]
    return F[:20]


def llm_answer(question, key):
    """Claude narrates the computed findings, then a non-LLM verifier audits it."""
    ev = findings_for(key)
    with st.spinner("Claude is writing the answer from the computed findings..."):
        try:
            prose = llm_layer.narrate(question, ev)
        except Exception as e:
            st.warning(f"LLM unavailable ({e}). Showing the deterministic answer.")
            render_answer(key)
            return
        ok, problems = llm_layer.verify(prose, ev)

    if ok:
        st.markdown(prose)
        st.success(f"✅ **Verifier passed** — every CVE, asset and CVSS score in "
                   f"this answer appears in the {len(ev)} evidence rows the engine "
                   f"computed. No fabricated identifiers.")
    else:
        st.error("❌ **Verifier failed** — the generated text referenced data that "
                 "is not in the evidence set. Showing the deterministic answer "
                 "instead.")
        for p in problems:
            st.markdown(f"- `{p}`")
        with st.expander("Show the rejected text"):
            st.markdown(prose)
        st.markdown("---")
        render_answer(key)

    with st.expander(f"🔎 Evidence the model was given ({len(ev)} findings)"):
        st.dataframe(pd.DataFrame([{
            "asset": f["asset_id"], "product": f["product"], "version": f["version"],
            "CVE": f["cve"], "CVSS": f["cvss"], "KEV": f["in_kev"],
            "due": f["due"], "confidence": f["confidence"], "risk": f["risk"]}
            for f in ev]), use_container_width=True, hide_index=True)


def render_answer(key):
    i = ORDER.index(key)
    if i == 0:
        crit = [f for f in F if f["cvss"] >= 9.0]
        cc = [f for f in crit if f["confidence"] == "confirmed"]
        cv = [f for f in crit if f["confidence"] != "confirmed"]
        st.success(f"**{len(cc)} confirmed** critical findings across "
                   f"{len({f['asset_id'] for f in cc})} assets, plus **{len(cv)}** "
                   f"that need verification across "
                   f"{len({f['asset_id'] for f in cv})} assets.")
        st.markdown("#### Confirmed")
        for f in cc:
            st.markdown(finding_card(f), unsafe_allow_html=True)
        if cv:
            st.markdown("#### Needs verification")
            for f in cv:
                st.markdown(finding_card(f), unsafe_allow_html=True)
        st.caption("Assumption: 'unpatched' is inferred from the installed version "
                   "being in an affected range — the inventory records no patch/KB state.")

    elif i == 1:
        srv = [f for f in F if f["asset_type"] == "server"]
        t = srv[0]
        st.success(f"**{t['asset_id']}** ({t['hostname']}) — {t['department']}, "
                   f"{t['criticality']} criticality — risk {t['risk']:.0f}/100")
        a, b = st.columns(2)
        with a:
            st.bar_chart(pd.DataFrame(
                [{"component": k, "points": v} for k, v in t["breakdown"].items()]
            ).set_index("component"), horizontal=True, height=230)
        with b:
            for k, v in t["breakdown"].items():
                st.markdown(f"- `{k}` **+{v}**")
            st.markdown(f"- subtotal **{t['raw_risk']}**")
            st.markdown(f"- confidence weight **×{t['conf_weight']}** "
                        f"({t['confidence']})")
            st.markdown(f"**TOTAL {t['risk']:.0f}/100** {band_pill(t['band'])}",
                        unsafe_allow_html=True)
        st.info(f"**Driver:** {t['cve']} — {t['why']}")
        for f in [x for x in srv if x["asset_id"] == t["asset_id"]][1:]:
            st.markdown(finding_card(f), unsafe_allow_html=True)

    elif i == 2:
        byp = {}
        for f in F:
            byp.setdefault(f["product"], []).append(f)
        rows = [{"package": p,
                 "worst item": max(x["risk"] for x in fs),
                 "total risk removed": round(sum(x["risk"] for x in fs)),
                 "hosts": len({x["asset_id"] for x in fs}),
                 "CVEs": len({x["cve"] for x in fs}),
                 "KEV": sum(1 for x in fs if x["in_kev"]),
                 "unconfirmed": sum(1 for x in fs if x["confidence"] != "confirmed"),
                 "overdue": any(x["overdue"] for x in fs)} for p, fs in byp.items()]
        rows.sort(key=lambda r: -r["total risk removed"])
        top_total = rows[0]
        top_worst = max(rows, key=lambda r: r["worst item"])
        a, b = st.columns(2)
        a.success(f"**Most exposure removed:** {top_total['package']} — "
                  f"{top_total['total risk removed']} points across "
                  f"{top_total['hosts']} hosts")
        b.warning(f"**Worst single item:** {top_worst['package']} — "
                  f"{top_worst['worst item']:.0f}/100")
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True,
                     column_config={
                         "worst item": st.column_config.ProgressColumn(
                             "worst item", min_value=0, max_value=100, format="%.0f")})
        st.caption("Two rankings because they answer different questions: **total** = "
                   "most exposure removed fleet-wide; **worst** = the single item most "
                   "likely to hurt you first.")

    elif i == 3:
        fin = [f for f in F if f["department"] == "Finance" and f["in_kev"]]
        fc = sorted({f["asset_id"] for f in fin if f["confidence"] == "confirmed"})
        fu = sorted({f["asset_id"] for f in fin
                     if f["confidence"] != "confirmed"} - set(fc))
        tot = len([a for a in assets if a["department"] == "Finance"])
        st.success(f"**{len(fc)} of {tot}** Finance assets have confirmed KEV "
                   f"exposure ({', '.join(fc)})."
                   + (f" A further **{len(fu)}** need verification "
                      f"({', '.join(fu)})." if fu else ""))
        st.caption(f"{len(fin)} matched KEV findings — one asset can carry several CVEs.")
        for f in fin:
            st.markdown(finding_card(f), unsafe_allow_html=True)

    elif i == 4:
        st.error(f"**Yes — {len(od)} findings across "
                 f"{len({f['asset_id'] for f in od})} assets** are past their CISA "
                 f"deadline as of {AS_OF}.")
        st.dataframe(pd.DataFrame([{
            "asset": f["asset_id"], "CVE": f["cve"], "product": f["product"],
            "version": f["version"], "confidence": f["confidence"], "due": f["due"],
            "days overdue": (AS_OF - datetime.strptime(f["due"], "%Y-%m-%d").date()).days,
            "risk": f["risk"]} for f in sorted(od, key=lambda x: x["due"])]),
            use_container_width=True, hide_index=True)

    elif i == 5:
        kassets = {f["asset_id"] for f in kevf}
        ca = {f["asset_id"] for f in kevf if f["criticality"] == "critical"}
        oldest = max((AS_OF - datetime.strptime(f["due"], "%Y-%m-%d").date()).days
                     for f in od)
        byp = {}
        for f in F:
            byp.setdefault(f["product"], []).append(f)
        first = max(byp.items(), key=lambda kv: sum(x["risk"] for x in kv[1]))[0]
        st.markdown(f"""
> **1.** Across **{len(assets)} assets** we confirmed **{len(conf)} findings** and
> flagged a further **{len(likely) + len(unc)}** requiring configuration or platform
> verification, covering **{len({f['cve'] for f in F})} distinct CVEs** of which
> **{len({f['cve'] for f in kevf})}** are on CISA's Known Exploited Vulnerabilities list.
>
> **2.** **{len(kassets)} assets** carry at least one actively-exploited CVE —
> **{len(ca)} of them business-critical** — and every matched KEV deadline has already
> passed, the oldest by **{oldest:,} days**.
>
> **3.** Patch **{first}** first, then validate the
> **{len(likely) + len(unc)}** configuration-dependent findings; this covers
> {len({r['product'] for r in solve.RULES})} high-signal packages and excludes
> operating-system patching, so it is a **floor** on exposure, not a complete picture.
""")

    elif i == 6:
        byd, dtot = {}, {}
        for f in F:
            byd.setdefault(f["department"], []).append(f)
        for a in assets:
            dtot[a["department"]] = dtot.get(a["department"], 0) + 1
        rows = [{"unit": d, "worst item": max(x["risk"] for x in fs),
                 "total risk": round(sum(x["risk"] for x in fs)),
                 "findings": len(fs), "KEV": sum(1 for x in fs if x["in_kev"]),
                 "unconfirmed": sum(1 for x in fs if x["confidence"] != "confirmed"),
                 "assets hit": f"{len({x['asset_id'] for x in fs})}/{dtot[d]}",
                 "critical assets": len({x["asset_id"] for x in fs
                                         if x["criticality"] == "critical"})}
                for d, fs in byd.items()]
        rows.sort(key=lambda r: -r["total risk"])
        st.success(f"**{rows[0]['unit']}** — highest aggregate exposure "
                   f"({rows[0]['total risk']} risk points), "
                   f"{rows[0]['critical assets']} business-critical assets affected.")
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True,
                     column_config={"worst item": st.column_config.ProgressColumn(
                         "worst item", min_value=0, max_value=100, format="%.0f")})

    elif i == 7:
        ap = [f for f in F if f["product"] == "Apache HTTP Server"]
        rest = {f["cve"] for f in F if f["product"] != "Apache HTTP Server"}
        before = len({f["cve"] for f in F})
        m = st.columns(4)
        m[0].metric("Hosts affected", len({f["asset_id"] for f in ap}))
        m[1].metric("CVEs closed", len({f["cve"] for f in ap}))
        m[2].metric("Fleet CVEs", f"{before} → {len(rest)}",
                    delta=-(before - len(rest)))
        m[3].metric("Risk removed", f"{sum(f['risk'] for f in ap):.0f}")
        for f in ap:
            st.markdown(finding_card(f), unsafe_allow_html=True)
        st.info("One action — *upgrade Apache to 2.4.58+ on FIN-SRV-001* — closes both.")

    elif i == 8:
        nd = sorted([f for f in F if f["asset_type"] == "network_device"],
                    key=lambda x: -x["cvss"])
        st.success(f"**{len(nd)} CVEs** across "
                   f"{len({f['asset_id'] for f in nd})} network devices.")
        for f in nd:
            st.markdown(finding_card(f), unsafe_allow_html=True)
        st.warning("Every network-device finding depends on management / Web UI / "
                   "SSL-VPN exposure that the inventory does not record. None are "
                   "presented as certain exploitation paths.")

    elif i == 9:
        stale = {}
        for f in F:
            if f["cvss"] < 7.0:
                continue
            age = (AS_OF - datetime.strptime(f["last_scan"], "%Y-%m-%d").date()).days
            if age >= 30:
                stale.setdefault(f["asset_id"], {"age": age, "f": []})["f"].append(f)
        st.success(f"**{len(stale)} assets** are both >30 days from their last scan "
                   f"and carry a high/critical finding, as of {AS_OF}.")
        st.dataframe(pd.DataFrame([{
            "asset": k, "last scan": v["f"][0]["last_scan"],
            "days since scan": v["age"], "criticality": v["f"][0]["criticality"],
            "HIGH+ findings": len(v["f"]),
            "worst risk": max(x["risk"] for x in v["f"])}
            for k, v in sorted(stale.items(),
                               key=lambda kv: -max(x["risk"] for x in kv[1]["f"]))]),
            use_container_width=True, hide_index=True)
        st.caption(f"Scan dates across the fleet span "
                   f"{min(a['last_scan_date'] for a in assets)} to "
                   f"{max(a['last_scan_date'] for a in assets)}.")

    elif i == 10:
        st.warning("**I cannot answer this from the data provided.**")
        st.markdown(f"""
Computing change requires **at least two inventory snapshots**, plus the
vulnerability-feed revision used at each point in time. This dataset is a single
snapshot and CISA KEV is fetched live, so any trend I reported would be **fabricated**.

**What I can state:** exposure as of **{AS_OF}** is **{len(F)} findings** across
**{len({f['asset_id'] for f in F})} assets**.

**To enable this:** persist each run's findings and diff on `(asset_id, cve)`.
That gives genuine new / resolved / unchanged counts.
""")

    else:
        covered = {r["product"] for r in solve.RULES}
        allsw = sorted({s["name"] for a in assets for s in a["installed_software"]})
        missing = [s for s in allsw if s not in covered]
        st.error(f"**{len(missing)} of {len(allsw)} packages have no detection rule.** "
                 f"Absence of a finding for these is *not* evidence of safety — it "
                 f"means we did not check.")
        st.dataframe(pd.DataFrame({"package (not assessed)": missing}),
                     use_container_width=True, hide_index=True, height=280)
        st.caption("Full reasoning is in the **Data quality & limits** tab.")


with t_ask:
    st.markdown("#### Ask the analyst")
    typed = st.text_input(
        "Ask anything about your exposure",
        placeholder="e.g. what should we patch first?  ·  whats our riskiest server?  "
                    "·  anything overdue?",
        label_visibility="collapsed")

    key, conf = solve.route_question(typed) if typed.strip() else (None, 0.0)

    if typed.strip() and key:
        st.caption(f"Interpreted as: **{QMAP[key]}**"
                   + ("" if conf >= 1.0 else f"  ·  fuzzy match (confidence {conf})"))
        st.write("")
        if use_llm:
            llm_answer(typed, key)
        else:
            render_answer(key)

    elif typed.strip() and not key:
        # Graceful degradation: say we didn't understand, then show something
        # genuinely useful rather than guessing at the question.
        st.info("I'm not certain what you're asking. Here are the highest-risk "
                "findings right now — or try one of the examples below.")
        for f in F[:5]:
            st.markdown(finding_card(f), unsafe_allow_html=True)
        st.markdown("**Try:** *what should we patch first* · *whats our riskiest "
                    "server* · *anything overdue* · *summarise for the CISO* · "
                    "*what did you not assess*")

    else:
        st.caption("Type a question above, or pick an example:")
        picked = st.selectbox("Example questions", ORDER,
                              format_func=lambda k: QMAP[k],
                              label_visibility="collapsed")
        st.write("")
        if use_llm:
            llm_answer(QMAP[picked], picked)
        else:
            render_answer(picked)

# ========================= REMEDIATION QUEUE ==============================
with t_q:
    st.markdown("#### Monday-morning remediation queue")
    st.caption("Ranked by confidence-weighted risk. Every row carries its full "
               "evidence trail — asset, product, CVE, CVSS, KEV status, CISA deadline.")
    if not view:
        st.info("No findings match the current filters.")
    else:
        st.dataframe(pd.DataFrame([{
            "risk": f["risk"], "band": f["band"], "confidence": f["confidence"],
            "asset": f["asset_id"], "hostname": f["hostname"],
            "unit": f["department"], "criticality": f["criticality"],
            "product": f["product"], "version": f["version"], "CVE": f["cve"],
            "CVSS": f["cvss"], "KEV": "yes" if f["in_kev"] else "no",
            "ransomware": "yes" if f["ransomware"] else "",
            "CISA due": f["due"] or "",
            "overdue": "OVERDUE" if f["overdue"] else "",
            "needs verification": f["caveat"] or ""} for f in view]),
            use_container_width=True, hide_index=True, height=520,
            column_config={"risk": st.column_config.ProgressColumn(
                "risk", min_value=0, max_value=100, format="%.0f")})
        st.download_button("Download queue as CSV",
                           pd.DataFrame(view).to_csv(index=False).encode(),
                           file_name="remediation_queue.csv", mime="text/csv")

    with st.expander("Scoring model"):
        st.markdown("""
| Component | Max | Rationale |
|---|---:|---|
| CVSS severity | 30 | Capped — CVSS alone produced the client's unusable 3,400-item list |
| Exploitation (CISA KEV) | 30 | Equal weight to severity: a 7.5 under active attack beats a theoretical 9.8 |
| Asset criticality | 25 | Business impact of the host |
| Deadline urgency | 15 | CISA due-date proximity / overdue |

The subtotal is then multiplied by a **confidence weight** — confirmed ×1.00,
likely ×0.85, uncertain ×0.70 — so an unverified finding is never ranked as fact.

**Known gap:** network exposure (internet-facing vs internal) is one of the strongest
real prioritisation signals and is absent from the inventory, so it contributes nothing.
""")

# ========================== BUSINESS UNITS ================================
with t_bu:
    byd, dtot = {}, {}
    for f in F:
        byd.setdefault(f["department"], []).append(f)
    for a in assets:
        dtot[a["department"]] = dtot.get(a["department"], 0) + 1
    rows = [{"unit": d, "worst item": max(x["risk"] for x in fs),
             "total risk": round(sum(x["risk"] for x in fs)), "findings": len(fs),
             "KEV": sum(1 for x in fs if x["in_kev"]),
             "assets affected": len({x["asset_id"] for x in fs}),
             "assets total": dtot[d],
             "critical assets hit": len({x["asset_id"] for x in fs
                                         if x["criticality"] == "critical"})}
            for d, fs in byd.items()]
    rows.sort(key=lambda r: -r["total risk"])
    a, b = st.columns([3, 2])
    a.markdown("#### Exposure by business unit")
    a.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True,
                column_config={"worst item": st.column_config.ProgressColumn(
                    "worst item", min_value=0, max_value=100, format="%.0f")})
    b.markdown("#### Actively-exploited findings")
    b.bar_chart(pd.DataFrame(rows).set_index("unit")[["KEV"]], height=300)

    st.markdown("#### Every asset")
    arows = []
    for a_ in assets:
        af = [f for f in F if f["asset_id"] == a_["asset_id"]]
        arows.append({"asset": a_["asset_id"], "hostname": a_["hostname"],
                      "unit": a_["department"], "type": a_["asset_type"],
                      "os": a_["os"], "criticality": a_["criticality"],
                      "last scan": a_["last_scan_date"], "findings": len(af),
                      "KEV": sum(1 for x in af if x["in_kev"]),
                      "worst risk": max([x["risk"] for x in af], default=0)})
    arows.sort(key=lambda r: -r["worst risk"])
    st.dataframe(pd.DataFrame(arows), use_container_width=True, hide_index=True)

# ======================= DATA QUALITY & LIMITS ============================
with t_dq:
    st.markdown("#### Data-quality findings")
    st.caption("Checks run against the inventory itself, before any vulnerability "
               "finding is trusted.")
    sev = {"high": "🔴", "medium": "🟠", "low": "🟡"}
    for d in DQ:
        st.markdown(f"""<div class='card'>{sev[d['severity']]} <b>{d['summary']}</b>
<br/><span class='muted'>{d['detail']}<br/><b>Impact:</b> {d['impact']}</span></div>""",
                    unsafe_allow_html=True)

    st.markdown("#### Coverage")
    covered = {r["product"] for r in solve.RULES}
    allsw = sorted({s["name"] for a in assets for s in a["installed_software"]})
    missing = [s for s in allsw if s not in covered]
    m = st.columns(3)
    m[0].metric("Packages with rules", len(covered))
    m[1].metric("Packages in inventory", len(allsw))
    m[2].metric("Not assessed", len(missing))
    st.error("Absence of a finding for the packages below is **not** evidence of "
             "safety. It means we did not check. Conflating those two is how "
             "vulnerability programmes lose credibility.")
    st.dataframe(pd.DataFrame({"package (not assessed)": missing}),
                 use_container_width=True, hide_index=True, height=260)

    st.markdown("""
#### Deliberate scope decisions

**Operating systems are excluded.** Pulling every Windows/RHEL CVE returns hundreds of
results and recreates the 3,400-finding noise problem this tool exists to fix. OS
patching also runs on a separate workflow (Patch Tuesday → WSUS/MECM/Satellite).

**Java SE is excluded.** NVD identifies it as `1.8.0:update_271`; the inventory says
`8.0.271`. Reconciling those by guesswork produces confident-but-wrong applicability,
so it is flagged for manual review instead.

**Browsers get one CVE, not their whole history.** Querying NVD by CPE for Chrome 114
returns ~2,300 technically-applicable CVEs — every issue fixed in any later release.
Instead we carry the single KEV-listed libwebp flaw (`CVE-2023-4863`), which is what
actually needs actioning.

**Analysis is anchored to the newest scan date, not today.** Using wall-clock time makes
"days overdue" drift on every run. Anchoring to the data's own most recent observation
means the same input always produces the same report.

#### Where this can still fail

1. **Version rules are hand-curated** — a wrong rule produces a confidently wrong finding.
2. **Inventory accuracy is assumed** — if the CMDB says 2.4.49 and the host runs 2.4.58,
   every downstream conclusion is wrong. Production needs authenticated scan data.
3. **Confidence tiers encode judgement, not measurement** — "likely" reflects our reading
   of what the exploit requires, not a probe of the host.
4. **No EPSS** — exploit-prediction scoring would improve ranking of non-KEV findings.
5. **No attack-path context** — "this workstation is one hop from the DC" doesn't affect
   ranking yet.
""")

# ========================== HOW AI IS USED ================================
with t_ai:
    st.markdown("#### Where AI is used — and deliberately where it is not")
    ok, msg = llm_layer.status()
    (st.success if ok else st.info)(
        f"{'🟢' if ok else '⚪'} **{msg}.** "
        + ("Toggle *Use Claude to write answers* in the sidebar."
           if ok else "The app runs fully without it — set `ANTHROPIC_API_KEY` "
                      "and `pip install anthropic` to enable narration."))

    st.markdown("""
```
question ──► ROUTE ──► [ deterministic engine ] ──► NARRATE ──► VERIFY ──► answer
             (LLM or      matching · scoring         (LLM or     (never
              keywords)    KEV lookup · dates       templates)    an LLM)
                                  ▲
                          NO LLM TOUCHES THIS
```

**The load-bearing decision: the LLM never produces a security fact.**

| Stage | Who does it | Why |
|---|---|---|
| Version → CVE applicability | Python, explicit NVD-sourced ranges | Reproducible and checkable |
| KEV status, due dates, ransomware | Live CISA feed | Authoritative |
| Risk scoring | Transparent additive formula | Auditable, and arguable by the client |
| **Question → intent** | **Claude** (or keyword router) | Genuinely ambiguous; LLMs are good at it |
| **Rows → prose** | **Claude** (or templates) | Genuinely a language task |
| **Citation audit** | **Regex over the evidence set** | An LLM cannot be its own auditor |

An LLM that cannot reach the numbers cannot get the numbers wrong.
""")

    a, b = st.columns(2)
    with a:
        st.markdown("##### Why not let the model do more?")
        st.markdown("""
The client's failure was a scanner producing **3,400 unprioritised findings**
that the team learned to ignore. The way to make that *worse* is a system that
sounds authoritative and occasionally invents a CVE.

Trust, once lost, is not recovered by a better model.

So scoring and matching stay deterministic: **two analysts running the same
query get identical numbers**. That is a precondition for a CISO signing off
on a remediation sprint.
""")
    with b:
        st.markdown("##### The verifier")
        st.markdown("""
Every generated answer is scanned for **CVE IDs, asset IDs and CVSS scores**,
and each is checked against the evidence rows the engine computed.

If the model references anything it was not given, the answer is **rejected**
and the deterministic answer is shown instead — with the rejected text kept
visible for inspection.

It catches fabricated identifiers. It **cannot** catch prose that cites real
CVEs but characterises them misleadingly — a real limit, stated plainly.
""")

    st.markdown("##### Graceful degradation")
    st.info("With no API key the application still answers all 12 questions via "
            "the keyword router and templates. **The LLM is an enhancement, never "
            "a dependency** — a security tool that stops working when an external "
            "API is down is not a security tool.")

    with st.expander("The exact prompts (system messages sent to Claude)"):
        st.markdown("**Router** — picks from a fixed enum, cannot invent an intent:")
        st.code(llm_layer.ROUTER_SYSTEM, language="text")
        st.markdown("**Narrator** — grounded in supplied evidence only:")
        st.code(llm_layer.NARRATOR_SYSTEM, language="text")

    with st.expander("Verifier source (llm_layer.verify)"):
        st.code('''_CVE_RE   = re.compile(r"CVE-\\d{4}-\\d{4,7}", re.I)
_ASSET_RE = re.compile(r"\\b[A-Z]{2,4}-(?:SRV|WS|NET)-\\d{3}\\b")
_CVSS_RE  = re.compile(r"CVSS\\s*([0-9]{1,2}(?:\\.[0-9])?)", re.I)

def verify(text, findings):
    problems  = []
    ok_cves   = {f["cve"].upper() for f in findings}
    ok_assets = {f["asset_id"]    for f in findings}
    ok_cvss   = {str(f["cvss"])   for f in findings}

    for c in {m.upper() for m in _CVE_RE.findall(text)}:
        if c not in ok_cves:
            problems.append(f"UNSUPPORTED CVE: {c} is not in the evidence set.")
    for a in set(_ASSET_RE.findall(text)):
        if a not in ok_assets:
            problems.append(f"UNSUPPORTED ASSET: {a} is not in the evidence set.")
    for s in set(_CVSS_RE.findall(text)):
        if s not in ok_cvss:
            problems.append(f"UNSUPPORTED CVSS: {s} matches no score in evidence.")

    return (not problems), problems''', language="python")

st.markdown("---")
st.caption(f"assets.json · CISA KEV {kev_raw['catalogVersion']} ({kev_mode}, "
           f"{len(kevidx):,} exploited CVEs, released {kev_raw['dateReleased'][:10]}) "
           f"· analysis date {AS_OF}")
