"""Clients for the CISA KEV catalog and the NIST NVD API.

Standard library only, on purpose: the interviewer should be able to run this
with a bare Python install and no `pip install` step.

Division of authority between the two feeds -- this matters, because each is
authoritative for something different and neither is sufficient alone:

  CISA KEV  -> "is this CVE being exploited in the wild, and by when must a
               federal agency fix it". Carries no CVSS score and no version
               ranges, so KEV *cannot* tell you whether YOUR version is
               affected. Using KEV alone produces false positives.

  NIST NVD  -> CVSS scores and, critically, CPE version applicability. Asking
               NVD for `virtualMatchString=cpe:2.3:a:apache:log4j:2.14.1`
               makes NVD itself adjudicate whether that exact version is in
               range, rather than us re-implementing vendor version algebra.

So: NVD decides *whether it applies*, KEV decides *how urgent it is*.
"""

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

USER_AGENT = "ctem-exposure-prototype/0.1 (interview artifact)"

# NVD allows 5 requests / 30s unauthenticated, 50 / 30s with an API key.
# Measured behaviour: NVD signals throttling with 503 rather than 429, and a
# burst that exceeds the limit poisons the next several requests. We therefore
# sit well under the documented ceiling (8s => ~3.7 req/30s) and back off hard
# rather than retrying quickly, because fast retries make throttling worse.
_DELAY_NO_KEY = 12.0
_DELAY_WITH_KEY = 1.0


class FeedError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# TLS trust store
# --------------------------------------------------------------------------
# Some Python installations (notably Windows) ship without a usable CA file,
# or with an expired one, so every HTTPS call fails with
# CERTIFICATE_VERIFY_FAILED. We search for a valid bundle rather than
# disabling verification: a tool that tells you which CVEs you are exposed to
# has no business silently accepting unverified TLS.
_CA_CANDIDATES = [
    os.environ.get("SSL_CERT_FILE"),
    os.environ.get("REQUESTS_CA_BUNDLE"),
    r"C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt",
    r"C:\Program Files\Git\mingw64\ssl\certs\ca-bundle.crt",
    "/usr/ssl/certs/ca-bundle.crt",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
]


def _build_ssl_context() -> ssl.SSLContext:
    """Resolve a CA bundle, preferring an explicit one over the system default.

    Note on ordering: we do NOT probe the default store with
    cert_store_stats(). A store containing an *expired* root still reports a
    non-zero CA count, so counting certificates proves the store is populated,
    not that it can validate anything. That check passes on exactly the broken
    machines it was meant to catch. Preferring a known-good explicit bundle
    (the same thing requests/certifi does) is both simpler and correct.
    """
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass

    for path in _CA_CANDIDATES:
        if path and os.path.exists(path):
            try:
                return ssl.create_default_context(cafile=path)
            except Exception:
                continue
    return ssl.create_default_context()


_SSL_CONTEXT = _build_ssl_context()


def _get(url: str, params: Optional[dict] = None, headers: Optional[dict] = None,
         attempts: int = 6, timeout: int = 90) -> dict:
    """HTTP GET returning parsed JSON, with backoff.

    NVD returns 503 frequently and without pattern, including for requests
    that succeed on immediate retry. Treating a single 503 as failure would
    make the index build non-deterministic, so we retry generously.
    """
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})

    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CONTEXT) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            # 403/404 are terminal; 429/5xx are worth retrying.
            if e.code in (403, 404):
                raise FeedError(f"{last} for {url}") from e
        except urllib.error.URLError as e:
            # A TLS trust failure is deterministic: retrying it 6 times with
            # escalating backoff burns minutes to arrive at the same error.
            # Fail fast and say what to do about it.
            if isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
                raise FeedError(
                    f"TLS certificate verification failed for {url}. This Python "
                    f"install has no usable CA bundle. Fix by installing certifi "
                    f"(`pip install certifi`) or setting SSL_CERT_FILE to a valid "
                    f"CA bundle. Original error: {e.reason}"
                ) from e
            last = f"{type(e).__name__}: {e}"
        except Exception as e:  # timeout, malformed JSON, transient socket error
            last = f"{type(e).__name__}: {e}"
        if i < attempts - 1:
            # Long, escalating waits. NVD throttling clears on the order of
            # tens of seconds; retrying every 2s just extends the penalty.
            time.sleep(min(15 * (i + 1), 60))
    raise FeedError(f"failed after {attempts} attempts ({last}) for {url}")


# --------------------------------------------------------------------------
# CISA KEV
# --------------------------------------------------------------------------

def fetch_kev(cache_path: str, max_age_hours: int = 24, offline: bool = False) -> dict:
    """Return the KEV catalog, using the on-disk cache when it is fresh."""
    if os.path.exists(cache_path):
        age_h = (time.time() - os.path.getmtime(cache_path)) / 3600
        if offline or age_h < max_age_hours:
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
    if offline:
        raise FeedError("offline mode and no KEV cache present")

    data = _get(KEV_URL)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return data


def index_kev(kev: dict) -> Dict[str, dict]:
    """Map CVE ID -> KEV entry."""
    return {e["cveID"]: e for e in kev.get("vulnerabilities", [])}


# --------------------------------------------------------------------------
# NVD
# --------------------------------------------------------------------------

class NvdClient:
    """Rate-limited, disk-cached NVD client.

    The cache is keyed by the CPE match string, so re-running the pipeline is
    free and the demo does not depend on NVD being up.
    """

    def __init__(self, cache_dir: str, api_key: Optional[str] = None, offline: bool = False):
        self.cache_dir = cache_dir
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.offline = offline
        self.delay = _DELAY_WITH_KEY if self.api_key else _DELAY_NO_KEY
        self._last_call = 0.0
        self.calls = 0
        os.makedirs(cache_dir, exist_ok=True)

    def _cache_file(self, key: str) -> str:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in key)
        return os.path.join(self.cache_dir, f"{safe}.json")

    def _throttle(self) -> None:
        wait = self.delay - (time.time() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.time()

    def cves_for_cpe(self, cpe_match: str) -> Optional[dict]:
        """All NVD CVEs applicable to a specific CPE + version.

        Returns None when the lookup could not be completed (offline with no
        cache, or NVD persistently failing). None means "unknown", which the
        matcher must not confuse with "no vulnerabilities".
        """
        path = self._cache_file(cpe_match)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        if self.offline:
            return None

        headers = {"apiKey": self.api_key} if self.api_key else {}
        self._throttle()
        try:
            data = _get(NVD_URL, params={"virtualMatchString": cpe_match}, headers=headers)
        except FeedError:
            return None
        self.calls += 1

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return data


# --------------------------------------------------------------------------
# CVSS extraction
# --------------------------------------------------------------------------

# Preference order. NVD's own analysis ("Primary") is preferred over a CNA's
# secondary submission, because the two frequently disagree -- CVE-2021-41773
# is scored 9.8 by NVD and 7.5 by a secondary source. Picking silently would
# make the risk ranking unreproducible, so the choice is recorded on the
# finding and shown in the citation.
_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def extract_cvss(cve: dict) -> dict:
    """Pull the best available CVSS score, recording which one was used."""
    metrics = cve.get("metrics") or {}
    for key in _CVSS_KEYS:
        entries = metrics.get(key) or []
        # Prefer the NVD-authored (Primary) entry within each version.
        for want_primary in (True, False):
            for e in entries:
                if want_primary and e.get("type") != "Primary":
                    continue
                data = e.get("cvssData") or {}
                score = data.get("baseScore")
                if score is None:
                    continue
                return {
                    "score": float(score),
                    "severity": (data.get("baseSeverity")
                                 or _severity_from_score(float(score))).upper(),
                    "vector": data.get("vectorString"),
                    "metric": key.replace("cvssMetric", "CVSS "),
                    "source": e.get("type", "Unknown"),
                }
    return {"score": None, "severity": "UNKNOWN", "vector": None,
            "metric": None, "source": None}


def _severity_from_score(s: float) -> str:
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0:
        return "LOW"
    return "NONE"


def english_description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""
