import subprocess

from .probe import PROBE_SCRIPT, parse_probe


def run_local(timeout=60):
    out = subprocess.run(["sh", "-c", PROBE_SCRIPT], capture_output=True, text=True, timeout=timeout)
    return parse_probe(out.stdout)
