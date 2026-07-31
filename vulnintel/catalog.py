"""Inventory software name -> CPE identity mapping.

This is the single most important source of *systematic* error in the whole
pipeline, so it is a hand-curated table rather than a fuzzy matcher.

Rationale: an asset inventory says "Apache HTTP Server"; NVD says
"cpe:2.3:a:apache:http_server". Bridging those two namespaces is the classic
vulnerability-management correlation problem. A fuzzy string matcher will
silently produce both false positives (Cisco "IOS" matching Apple "iOS") and
false negatives, and neither is visible to the analyst. A curated table is
smaller in coverage but every gap is *known* and can be reported.

Anything not in this table is reported as UNMAPPED, never as "no findings".
That distinction is the difference between "we checked and you are clean" and
"we did not check", and conflating them is how vulnerability programmes lose
credibility.

SCOPE CUT: operating systems are deliberately excluded from CVE matching.
Two reasons, one practical and one process-driven:
  1. Querying NVD for "Windows Server 2019" returns many hundreds of CVEs,
     which reproduces exactly the 3,400-finding noise problem we were hired
     to solve.
  2. OS patching is already driven by a different, well-established workflow
     (Patch Tuesday -> WSUS/MECM/Satellite) with its own cadence and owners.
     Application and middleware CVEs are the ones that fall between the
     cracks, so that is where an exposure tool adds marginal value.
This is a scope decision, not a claim that OS risk is zero. It is surfaced in
every coverage report.
"""

from typing import Dict, NamedTuple, Optional


class CpeIdentity(NamedTuple):
    vendor: str
    product: str
    part: str = "a"  # 'a' application, 'o' operating system, 'h' hardware
    note: Optional[str] = None

    @property
    def prefix(self) -> str:
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}"

    def virtual_match(self, version: str) -> str:
        return f"{self.prefix}:{version}"


# Keyed by the exact `name` field used in assets.json.
CATALOG: Dict[str, CpeIdentity] = {
    # --- Web / middleware -------------------------------------------------
    "Apache HTTP Server": CpeIdentity("apache", "http_server"),
    "Apache Tomcat": CpeIdentity("apache", "tomcat"),
    "NGINX": CpeIdentity("f5", "nginx"),
    "log4j-core": CpeIdentity("apache", "log4j"),
    # --- Crypto / transport ----------------------------------------------
    "OpenSSL": CpeIdentity("openssl", "openssl"),
    "OpenSSH": CpeIdentity("openbsd", "openssh"),
    "OpenSSH for Windows": CpeIdentity("openbsd", "openssh"),
    # --- Databases --------------------------------------------------------
    "PostgreSQL": CpeIdentity("postgresql", "postgresql"),
    "Microsoft SQL Server": CpeIdentity("microsoft", "sql_server"),
    # --- Runtimes / languages --------------------------------------------
    "Python": CpeIdentity("python", "python"),
    "Node.js": CpeIdentity("nodejs", "node.js"),
    "Ruby": CpeIdentity("ruby-lang", "ruby"),
    "OpenJDK": CpeIdentity("oracle", "openjdk"),
    # --- DevOps tooling ---------------------------------------------------
    "Jenkins": CpeIdentity("jenkins", "jenkins"),
    "GitLab CE": CpeIdentity("gitlab", "gitlab"),
    "Git": CpeIdentity("git-scm", "git"),
    "Docker": CpeIdentity("docker", "docker"),
    "Grafana": CpeIdentity("grafana", "grafana"),
    "Prometheus": CpeIdentity("prometheus", "prometheus"),
    "Sonatype Nexus Repository Manager": CpeIdentity("sonatype", "nexus"),
    # --- Microsoft desktop / server apps ---------------------------------
    "Microsoft Exchange Server": CpeIdentity("microsoft", "exchange_server"),
    "Microsoft Office": CpeIdentity("microsoft", "office"),
    "Internet Explorer": CpeIdentity("microsoft", "internet_explorer"),
    "Visual Studio Code": CpeIdentity("microsoft", "visual_studio_code"),
    "Microsoft .NET Framework": CpeIdentity("microsoft", ".net_framework"),
    # --- Browsers ---------------------------------------------------------
    "Google Chrome": CpeIdentity("google", "chrome"),
    "Mozilla Firefox": CpeIdentity("mozilla", "firefox"),
    # --- Endpoint / productivity -----------------------------------------
    "Adobe Acrobat Reader": CpeIdentity("adobe", "acrobat_reader_dc"),
    "7-Zip": CpeIdentity("7-zip", "7-zip"),
    "PuTTY": CpeIdentity("putty", "putty"),
    "WinSCP": CpeIdentity("winscp", "winscp"),
    "Zoom": CpeIdentity("zoom", "zoom"),
    "Nmap": CpeIdentity("nmap", "nmap"),
    # --- Network / infrastructure ----------------------------------------
    "Cisco IOS": CpeIdentity("cisco", "ios", part="o"),
    "Cisco IOS XE": CpeIdentity("cisco", "ios_xe", part="o"),
    "Fortinet FortiOS": CpeIdentity("fortinet", "fortios", part="o"),
    "F5 BIG-IP": CpeIdentity(
        "f5", "big-ip_local_traffic_manager",
        note="BIG-IP ships as many licensed modules with separate CPEs; LTM is "
             "used as the representative product. Module-specific CVEs may be missed.",
    ),
    "Veeam Backup & Replication": CpeIdentity("veeam", "backup_%26_replication"),
}

# Products present in the inventory that are deliberately NOT mapped, with the
# reason. Reported as coverage gaps so absence of findings is never read as
# absence of risk.
UNMAPPED_REASONS: Dict[str, str] = {
    "Java SE": (
        "Oracle Java versions in NVD use the form 1.8.0:update_271, but the "
        "inventory records 8.0.271. The two namespaces cannot be reconciled "
        "reliably without an explicit translation table, and guessing would "
        "produce confident-but-wrong applicability. Flagged for manual review."
    ),
    "Microsoft Office for Mac": (
        "NVD tracks Office for Mac under several product names with "
        "inconsistent version schemes (16.70 vs 2019/2021 branding)."
    ),
    "Active Directory Domain Services": "Role of Windows Server; covered by OS patching, which is out of scope.",
    "Microsoft DNS Server": "Role of Windows Server; covered by OS patching, which is out of scope.",
    "CrowdStrike Falcon Sensor": "Security agent with sparse NVD CPE coverage; vendor advisories are the authoritative source.",
    "Symantec Endpoint Protection": "Vendor CPE naming changed across the Broadcom acquisition; mapping is unreliable.",
    "1Password": "Sparse NVD CPE coverage for the desktop client.",
    "Homebrew": "Package manager; NVD coverage is negligible.",
    "Slack": "Desktop client CPE coverage in NVD is inconsistent.",
}


def lookup(name: str) -> Optional[CpeIdentity]:
    return CATALOG.get(name)


def coverage(names) -> dict:
    """Split a set of inventory product names into mapped / unmapped / unknown."""
    mapped, unmapped, unknown = [], [], []
    for n in sorted(set(names)):
        if n in CATALOG:
            mapped.append(n)
        elif n in UNMAPPED_REASONS:
            unmapped.append(n)
        else:
            unknown.append(n)
    return {"mapped": mapped, "unmapped": unmapped, "unknown": unknown}
