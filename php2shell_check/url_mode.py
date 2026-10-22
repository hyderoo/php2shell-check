"""Passive URL check: one GET per URL, no POST, no payloads.

A remote site hides most of what we need, so the result is a hint:
`unknown` is the normal outcome and never means safe.
"""
import urllib.request
import urllib.error
from urllib.parse import urlparse

from .versions import parse, assess

UA = "php2shell-check/0.1 (read-only version check)"
MAX_URLS = 20


def check_url(url, timeout=10, opener=None):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError(f"not an http(s) URL: {url}")
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(req, timeout=timeout) as r:
            headers, status = dict(r.headers.items()), r.status
    except urllib.error.HTTPError as e:  # error pages still carry headers
        headers, status = dict(e.headers.items()), e.code
    except Exception as e:
        return {"target": url, "status": "error", "reason": f"{type(e).__name__}: {e}"}
    lower = {k.lower(): v for k, v in headers.items()}
    powered = lower.get("x-powered-by", "")
    server = lower.get("server", "")
    evidence = {"http_status": status, "x-powered-by": powered, "server": server}
    version = parse(powered) if "php" in powered.lower() else None
    if version is None and "php/" in server.lower():
        version = parse(server.lower().split("php/", 1)[1])
    if version is None:
        reason = "no PHP version exposed in headers"
        return {"target": url, "status": "unknown", "reason": reason, "evidence": evidence}
    # headers do not say who built the binary, so never call it plain vulnerable on a low number
    v = assess(version, distro_build=True)
    return {"target": url, "status": v.status, "reason": v.reason + " (from response header)",
            "evidence": evidence}
