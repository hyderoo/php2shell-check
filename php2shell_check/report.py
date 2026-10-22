import json

ORDER = {"vulnerable": 0, "review": 1, "error": 2, "unknown": 3, "patched": 4, "note": 5}
ADVICE = {
    "vulnerable": "Upgrade PHP to 8.2.35, 8.3.36, 8.4.27 or 8.5.12, then restart every PHP worker.",
    "review": "Check your vendor's advisory for a backported fix, or move to a supported branch.",
    "error": "Check the error and rerun this target; it was not assessed.",
    "unknown": "Could not tell. Check on the host itself with `php -v` for the binary that serves web requests.",
    "note": "",
    "patched": "Version is at or above the fixed release. Make sure workers were restarted.",
}


def inventory_findings(inv, label):
    rows = []
    for rt in inv.runtimes:
        rows.append({"target": f"{label}:{rt.path}", "status": rt.verdict.status,
                     "reason": rt.verdict.reason, "evidence": {"banner": rt.banner, **rt.ini}})
    from .hardening import notes
    for rt in inv.runtimes:
        for n in notes(rt.ini, rt.version):
            rows.append({"target": f"{label}:{rt.path}", "status": "note", "reason": n})
    for c in inv.containers:
        rows.append({"target": f"{label}:container {c}", "status": "review",
                     "reason": "running container not inspected; its PHP is separate from the host. Run this tool inside it",
                     "advice": ""})
    if inv.in_container:
        rows.append({"target": label, "status": "note",
                     "reason": "running inside a container; host PHP and sibling containers are not visible"})
    for p in inv.procs:
        rows.append({"target": f"{label}:process", "status": "review",
                     "reason": f"shell spawned by a web worker: {p[:200]} (normal for apps that shell out, check it)",
                     "advice": "Compare with what the app is expected to run; correlate with request and error logs."})
    if not inv.complete:
        rows.append({"target": label, "status": "error", "reason": "inventory did not finish; results are incomplete"})
    for pkg in inv.packages:
        if pkg.startswith("libapache2-mod-php"):
            rows.append({"target": label, "status": "review", "reason": f"Apache PHP module installed: {pkg}; verify the loaded module and restart state separately"})
    if not inv.runtimes:
        rows.append({"target": label, "status": "unknown", "reason": "no PHP binaries found in PATH or common locations"})
    return rows


def worst(findings):
    real = [f["status"] for f in findings if f["status"] != "note"]
    return min(real, key=lambda s: ORDER.get(s, 2), default="unknown")


def to_json(findings, overall=None):
    return json.dumps({"overall": overall or worst(findings), "findings": findings}, indent=2)


def to_text(findings):
    lines = []
    for f in sorted(findings, key=lambda f: ORDER.get(f["status"], 2)):
        lines.append(f"[{f['status'].upper():10}] {f['target']}")
        lines.append(f"             {f['reason']}")
        advice = f.get("advice", ADVICE.get(f["status"], ""))
        if advice:
            lines.append(f"             -> {advice}")
    lines.append("")
    lines.append(f"overall: {worst(findings)}")
    return "\n".join(lines)


def exit_code(findings):
    return {"patched": 0, "error": 1, "unknown": 2, "review": 3, "vulnerable": 4}.get(worst(findings), 2)
