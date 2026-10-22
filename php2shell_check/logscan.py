"""Optional log scan for exploitation signals.

Signals come from the Datadog write-up. None of them proves an attack, so
every hit is reported as `review`, and no hit does not mean no attack.
"""
import re

MEM_FATAL = re.compile(r"Allowed memory size of \d+ bytes exhausted.*Unknown on line 0", re.I)
SEGV = re.compile(r"exit signal Segmentation fault|segfault", re.I)
UPLOAD_FIELD = re.compile(r"PHP_SESSION_UPLOAD_PROGRESS")

RULES = [
    ("memory-exhausted-during-init", MEM_FATAL,
     "memory exhaustion before any script ran ('Unknown on line 0')"),
    ("worker-segfault", SEGV, "web worker crashed with a segmentation fault"),
    ("upload-progress-field", UPLOAD_FIELD, "request text mentions PHP_SESSION_UPLOAD_PROGRESS"),
]
MAX_HITS_PER_RULE = 20


def scan_lines(lines, source="stdin"):
    hits, counts = [], {}
    for n, line in enumerate(lines, 1):
        for name, rx, why in RULES:
            if rx.search(line):
                counts[name] = counts.get(name, 0) + 1
                if counts[name] <= MAX_HITS_PER_RULE:
                    hits.append({"target": f"{source}:{n}", "status": "review", "reason": f"{name}: {why}",
                                 "advice": "Weak signal. Correlate with oversized POSTs, worker crashes and shells spawned by workers.",
                                 "evidence": {"line": line.strip()[:300]}})
    for name, total in counts.items():
        if total > MAX_HITS_PER_RULE:
            hits.append({"target": source, "status": "review",
                         "reason": f"{name}: {total} matches, showing first {MAX_HITS_PER_RULE}"})
    return hits


def scan_file(path):
    with open(path, "r", errors="replace") as f:
        return scan_lines(f, path)
