"""Distro fixed-package versions we can cite.

Only Ubuntu is covered, from Canonical's advisory:
https://ubuntu.com/blog/php2shell-vulnerability-fixes-available
Anything else (Debian, RHEL, Alpine, third-party repos) stays "review" until a
source is added here with a link.
"""
import re

UBUNTU_SOURCE = "https://ubuntu.com/blog/php2shell-vulnerability-fixes-available"

# (ubuntu VERSION_ID) -> (source package base, first fixed package version)
UBUNTU_FIXED = {
    "14.04": ("php5", "5.5.9+dfsg-1ubuntu4.29+esm18"),
    "16.04": ("php7.0", "7.0.33-0ubuntu0.16.04.16+esm22"),
    "18.04": ("php7.2", "7.2.24-0ubuntu0.18.04.17+esm14"),
    "20.04": ("php7.4", "7.4.3-4ubuntu2.29+esm5"),
    "22.04": ("php8.1", "8.1.2-1ubuntu2.28"),
    "24.04": ("php8.3", "8.3.6-0ubuntu0.24.04.13"),
    "26.04": ("php8.5", "8.5.4-0ubuntu1.5"),
    "26.10": ("php8.5", "8.5.9-0ubuntu2.1"),
}

_THIRD_PARTY = re.compile(r"sury|ondrej|remi", re.I)


def _order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_part(a, b):
    """Compare one upstream or revision string by the Debian rules."""
    while a or b:
        # non-digit prefix
        i = 0
        while (i < len(a) and not a[i].isdigit()) or (i < len(b) and not b[i].isdigit()):
            ca = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            cb = _order(b[i]) if i < len(b) and not b[i].isdigit() else 0
            if ca != cb:
                return -1 if ca < cb else 1
            i += 1
        a, b = a[i:], b[i:]
        # digit run
        ma, mb = re.match(r"\d*", a).group(), re.match(r"\d*", b).group()
        na, nb = int(ma or 0), int(mb or 0)
        if na != nb:
            return -1 if na < nb else 1
        a, b = a[len(ma):], b[len(mb):]
    return 0


def _split(v):
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, _, rev = v.rpartition("-") if "-" in v else (v, "", "")
    return epoch, upstream, rev


def compare_deb(a, b):
    """-1, 0, 1 like dpkg --compare-versions."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _cmp_part(ua, ub) or _cmp_part(ra, rb)


def ubuntu_verdict(version_id, branch, pkg_versions):
    """Return (status, reason) or None when the table cannot judge.

    branch: "8.3" style string of the runtime. pkg_versions: installed
    versions of packages whose name starts with the table's base.
    """
    entry = UBUNTU_FIXED.get(version_id)
    if not entry or not pkg_versions:
        return None
    base, fixed = entry
    if base != f"php{branch}" and not (base == "php5" and branch.startswith("5.")):
        return None
    if any(_THIRD_PARTY.search(v) or not re.search(r"-\d+ubuntu", v) for v in pkg_versions):
        return None  # PPA or rebuilt package: Ubuntu's number does not apply
    lowest = min(pkg_versions, key=lambda v: _key(v))
    if compare_deb(lowest, fixed) >= 0:
        return "patched", f"{lowest} >= Ubuntu {version_id} fix {fixed} ({UBUNTU_SOURCE})"
    return "vulnerable", f"{lowest} < Ubuntu {version_id} fix {fixed} ({UBUNTU_SOURCE})"


def _key(v):
    import functools
    return functools.cmp_to_key(compare_deb)(v)
