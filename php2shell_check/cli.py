import argparse
import sys

from . import report
from .local_mode import run_local
from .ssh_mode import run_ssh
from .url_mode import check_url, MAX_URLS

AUTH_HELP = "required: confirm you own this target or are allowed to test it"


def build_parser():
    p = argparse.ArgumentParser(prog="php2shell-check",
        description="Read-only check for PHP2Shell exposure (CVE-2026-109618, CVE-2026-109619).")
    p.add_argument("--format", choices=["text", "json"], default="text")
    sub = p.add_subparsers(dest="mode", required=True)
    sub.add_parser("local", help="inspect PHP installed on this machine")
    u = sub.add_parser("url", help="passive header check of one or more URLs")
    u.add_argument("urls", nargs="+")
    u.add_argument("--timeout", type=int, default=10)
    u.add_argument("--i-am-authorized", action="store_true", help=AUTH_HELP)
    s = sub.add_parser("ssh", help="inspect PHP on a remote host over SSH")
    s.add_argument("target", help="user@host")
    s.add_argument("--port", type=int, default=22)
    s.add_argument("--identity", help="path to a private key file")
    s.add_argument("--known-hosts", help="alternate known_hosts file")
    s.add_argument("--i-am-authorized", action="store_true", help=AUTH_HELP)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.mode in ("url", "ssh") and not args.i_am_authorized:
        print("refusing to touch a remote target without --i-am-authorized", file=sys.stderr)
        return 64
    try:
        if args.mode == "local":
            findings = report.inventory_findings(run_local(), "local")
        elif args.mode == "ssh":
            findings = report.inventory_findings(run_ssh(args.target, args.port, args.identity, args.known_hosts), args.target)
        else:
            if len(args.urls) > MAX_URLS:
                print(f"at most {MAX_URLS} URLs per run", file=sys.stderr)
                return 64
            findings = [check_url(u, args.timeout) for u in args.urls]
    except (ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(report.to_json(findings) if args.format == "json" else report.to_text(findings))
    return report.exit_code(findings)


if __name__ == "__main__":
    sys.exit(main())
