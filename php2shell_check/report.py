import json

ORDER = {"vulnerable": 0, "review": 1, "unknown": 2, "patched": 3}
ADVICE = {
    "vulnerable": "Upgrade PHP to 8.2.35, 8.3.36, 8.4.27 or 8.5.12, then restart every PHP worker.",
    "review": "Check your vendor's advisory for a backported fix, or move to a supported branch.",
    "unknown": "Could not tell. Check on the host itself with `php -v` for the binary that serves web requests.",
    "patched": "Version is at or above the fixed release. Make sure workers were restarted.",
}


def inventory_findings(inv, label):
    rows = []
    for rt in inv.runtimes:
        rows.append({"target": f"{label}:{rt.path}", "status": rt.verdict.status,
                     "reason": rt.verdict.reason, "evidence": {"banner": rt.banner, **rt.ini}})
    if not rows:
        rows.append({"target": label, "status": "unknown", "reason": "no PHP binaries found in PATH or common locations"})
    return rows


def worst(findings):
    return min((f["status"] for f in findings), key=lambda s: ORDER.get(s, 2), default="unknown")


def to_json(findings):
    return json.dumps({"overall": worst(findings), "findings": findings}, indent=2)


def to_text(findings):
    lines = []
    for f in sorted(findings, key=lambda f: ORDER.get(f["status"], 2)):
        lines.append(f"[{f['status'].upper():10}] {f['target']}")
        lines.append(f"             {f['reason']}")
        if f["status"] in ADVICE:
            lines.append(f"             -> {ADVICE[f['status']]}")
    lines.append("")
    lines.append(f"overall: {worst(findings)}")
    return "\n".join(lines)


def exit_code(findings):
    return {"patched": 0, "unknown": 2, "review": 3, "vulnerable": 4}.get(worst(findings), 2)
