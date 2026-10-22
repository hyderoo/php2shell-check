"""SSH inventory using the system ssh client.

Host keys are always checked (StrictHostKeyChecking=yes), so the host must
already be in known_hosts. Authentication is whatever ssh already has: a key,
an agent, or ~/.ssh/config. The tool never takes a password.
"""
import shlex
import subprocess

from .probe import PROBE_SCRIPT, parse_probe


def build_command(target, port=22, identity=None, known_hosts=None):
    if target.startswith("-"):
        raise ValueError("target must not start with '-'")
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "ConnectTimeout=10", "-p", str(int(port))]
    if identity:
        cmd += ["-i", identity, "-o", "IdentitiesOnly=yes"]
    if known_hosts:
        cmd += ["-o", f"UserKnownHostsFile={known_hosts}"]
    return cmd + ["--", target, "sh", "-s"]


def run_ssh(target, port=22, identity=None, known_hosts=None, timeout=90):
    cmd = build_command(target, port, identity, known_hosts)
    p = subprocess.run(cmd, input=PROBE_SCRIPT, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0 and "@@end" not in p.stdout:
        raise RuntimeError(f"ssh failed ({p.returncode}): {p.stderr.strip()[:300]}")
    return parse_probe(p.stdout)
