"""Version logic for CVE-2026-109618 / CVE-2026-109619 (PHP2Shell).

Fixed upstream releases per the PHP security announcement:
8.2.35, 8.3.36, 8.4.27, 8.5.12. PHP 8.1 and older get no upstream fix.
"""
import re
from dataclasses import dataclass

FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
BACKPORT_ONLY = {(7, 4), (8, 0), (8, 1)}

VERSION_RE = re.compile(r"(?<![\d.])(\d+)\.(\d+)\.(\d+)")


@dataclass(frozen=True)
class Verdict:
    status: str  # vulnerable | patched | unknown | review
    reason: str


def parse(text):
    """First x.y.z found in text, or None."""
    m = VERSION_RE.search(text or "")
    return tuple(int(g) for g in m.groups()) if m else None


def assess(version, distro_build=False):
    """Judge an upstream-style version tuple.

    distro_build: the binary came from a distro package. Those often backport
    fixes without bumping the version, so a low number is not proof.
    """
    if version is None:
        return Verdict("unknown", "no PHP version could be read")
    major_minor = version[:2]
    shown = ".".join(map(str, version))
    if major_minor in FIXED:
        fixed = FIXED[major_minor]
        if version >= fixed:
            return Verdict("patched", f"{shown} >= {'.'.join(map(str, fixed))}")
        if distro_build:
            return Verdict("review", f"{shown} is below upstream fix {'.'.join(map(str, fixed))}; "
                           "distro package may carry a backport, check the vendor advisory")
        return Verdict("vulnerable", f"{shown} is below fixed release {'.'.join(map(str, fixed))}")
    if major_minor in BACKPORT_ONLY or major_minor < (8, 2):
        return Verdict("review", f"{shown} is end-of-life with no upstream release; "
                       "only a vendor package or source backport can fix it")
    # newer than anything known (8.6+ etc.)
    return Verdict("review", f"{shown} is a branch this tool has no fix data for")
