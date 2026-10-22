"""Config notes from PHP's own temporary-mitigation guidance.

These are notes, never a verdict: the advisories say only patching fixes
the bugs. Source:
https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
"""


def notes(ini, version):
    out = []
    if ini.get("upload_progress", "") in ("1", "On", "on"):
        out.append("session.upload_progress.enabled is on (CVE-2026-109619 guidance: set it to 0, restart workers)")
    if version and version[:2] == (8, 5) and ini.get("fatal_error_backtraces", "") in ("1", "On", "on"):
        out.append("fatal_error_backtraces is on for PHP 8.5 (CVE-2026-109619 guidance: set it to 0)")
    ml = ini.get("memory_limit")
    if ml not in (None, ""):
        out.append(f"memory_limit={ml} (CLI value, the web SAPI may differ; limits do not replace patching)")
    return out
