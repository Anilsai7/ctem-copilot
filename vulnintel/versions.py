"""Version parsing and comparison.

Vendor version strings are not semver. This module handles the formats that
actually appear in the inventory:

    2.4.49          Apache
    1.1.1k          OpenSSL (letter suffix is significant: 1.1.1k < 1.1.1l)
    15.2(7)E3       Cisco IOS
    16.0.15928      Microsoft Office
    11.0.220        Internet Explorer
    2017.14.0.3048  SQL Server
    23.001.20093    Acrobat

Strategy: tokenize into alternating numeric and alphabetic runs, then compare
element-wise. Numeric tokens compare as integers, alphabetic tokens compare
lexicographically. This reproduces CPE ordering semantics for the cases we
care about, most importantly OpenSSL's letter suffixes.

Deliberate limitation: this is a heuristic, not a general vendor-version
algebra. When it cannot confidently order two versions it says so, and the
matcher degrades the finding to UNCERTAIN rather than guessing.
"""

import re
from typing import List, Optional, Union

Token = Union[int, str]

_TOKEN_RE = re.compile(r"(\d+|[A-Za-z]+)")

# Tokens that carry no ordering information and only add noise.
_NOISE = {"v", "version", "release", "rel", "build", "p", "sp"}


def parse(version: str) -> Optional[List[Token]]:
    """Tokenize a version string. Returns None if nothing usable is found."""
    if version is None:
        return None
    raw = str(version).strip()
    if not raw or raw.lower() in {"unknown", "n/a", "none", "-"}:
        return None

    tokens: List[Token] = []
    for tok in _TOKEN_RE.findall(raw):
        if tok.isdigit():
            tokens.append(int(tok))
        else:
            low = tok.lower()
            # A leading 'v' (as in "v2.4.49") is noise; a trailing letter
            # (as in "1.1.1k") is meaningful, so only drop noise at position 0.
            if low in _NOISE and not tokens:
                continue
            tokens.append(low)
    return tokens or None


def compare(a: str, b: str) -> Optional[int]:
    """Return -1, 0, or 1 for a<b, a==b, a>b. None if not comparable."""
    ta, tb = parse(a), parse(b)
    if ta is None or tb is None:
        return None

    for x, y in zip(ta, tb):
        if isinstance(x, int) and isinstance(y, int):
            if x != y:
                return -1 if x < y else 1
        elif isinstance(x, str) and isinstance(y, str):
            if x != y:
                return -1 if x < y else 1
        else:
            # Mixed numeric/alpha at the same position, e.g. "8.0u" vs "8.0.1".
            # Ordering here is genuinely ambiguous across vendors, so refuse.
            return None

    if len(ta) == len(tb):
        return 0
    # A longer version with a common prefix is the later release:
    # 1.0.2 < 1.0.2u, and 2.4 < 2.4.49.
    return -1 if len(ta) < len(tb) else 1


def in_range(
    version: str,
    start_including: Optional[str] = None,
    start_excluding: Optional[str] = None,
    end_including: Optional[str] = None,
    end_excluding: Optional[str] = None,
) -> Optional[bool]:
    """Test a version against an NVD CPE version range.

    Returns True/False, or None if any required comparison was inconclusive
    (which the caller must treat as uncertainty, not as a negative).
    """
    checks = (
        (start_including, lambda c: c >= 0),
        (start_excluding, lambda c: c > 0),
        (end_including, lambda c: c <= 0),
        (end_excluding, lambda c: c < 0),
    )
    for bound, ok in checks:
        if not bound or bound == "*":
            continue
        c = compare(version, bound)
        if c is None:
            return None
        if not ok(c):
            return False
    return True


def matches_cpe_version(installed: str, cpe_version: str) -> Optional[bool]:
    """Compare an installed version against the version field of a CPE URI.

    '*' and '-' are CPE wildcards meaning "any version", which on their own
    prove nothing about applicability; the caller handles those via ranges.
    """
    if cpe_version in {"*", "-", ""}:
        return None
    c = compare(installed, cpe_version)
    if c is None:
        return None
    return c == 0
