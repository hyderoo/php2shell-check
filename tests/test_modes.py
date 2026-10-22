import unittest
from contextlib import redirect_stdout, redirect_stderr
import io

from php2shell_check import cli, report
from php2shell_check.probe import parse_probe
from php2shell_check.ssh_mode import build_command
from php2shell_check.url_mode import check_url


class FakeResp:
    def __init__(self, headers, status=200):
        self.headers, self.status = headers, status
    def __enter__(self): return self
    def __exit__(self, *a): return False


SAMPLE = """@@host web1
@@bin /usr/bin/php8.3
PHP 8.3.6 (cli) (built: Jan  1 2026) (NTS)
@@ini upload_progress=1
@@ini memory_limit=128M
@@bin /usr/local/bin/php
PHP 8.5.12 (cli) (built: Oct 21 2026) (NTS)
@@pkg php8.3-cli 8.3.6-0ubuntu0.24.04.13
@@end
"""


class ProbeTests(unittest.TestCase):
    def test_parse_inventory(self):
        inv = parse_probe(SAMPLE)
        self.assertTrue(inv.complete)
        self.assertEqual(inv.host, "web1")
        self.assertEqual(len(inv.runtimes), 2)
        distro, upstream = inv.runtimes
        self.assertEqual(distro.verdict.status, "review")   # distro package, low version
        self.assertEqual(upstream.verdict.status, "patched")
        self.assertEqual(distro.ini["upload_progress"], "1")

    def test_empty_means_unknown(self):
        rows = report.inventory_findings(parse_probe("@@host x\n@@end\n"), "x")
        self.assertEqual(rows[0]["status"], "unknown")


class UrlTests(unittest.TestCase):
    def test_header_version(self):
        op = lambda req, timeout: FakeResp({"X-Powered-By": "PHP/8.2.20"})
        r = check_url("https://example.test/", opener=op)
        self.assertEqual(r["status"], "review")  # headers cannot prove who built it

    def test_no_header_is_unknown(self):
        op = lambda req, timeout: FakeResp({"Server": "nginx"})
        self.assertEqual(check_url("https://example.test/", opener=op)["status"], "unknown")

    def test_patched_header(self):
        op = lambda req, timeout: FakeResp({"X-Powered-By": "PHP/8.4.27"})
        self.assertEqual(check_url("https://example.test/", opener=op)["status"], "patched")

    def test_get_only_and_bad_scheme(self):
        seen = {}
        def op(req, timeout):
            seen["method"] = req.get_method(); return FakeResp({})
        check_url("http://example.test/", opener=op)
        self.assertEqual(seen["method"], "GET")
        with self.assertRaises(ValueError):
            check_url("file:///etc/passwd")


class SshTests(unittest.TestCase):
    def test_host_key_checking_and_no_password(self):
        cmd = build_command("me@host", 2222, "/k/id")
        self.assertIn("StrictHostKeyChecking=yes", cmd)
        self.assertIn("BatchMode=yes", cmd)
        self.assertEqual(cmd[cmd.index("-p") + 1], "2222")

    def test_option_injection_blocked(self):
        with self.assertRaises(ValueError):
            build_command("-oProxyCommand=evil")


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_remote_needs_authorization_flag(self):
        self.assertEqual(self.run_cli(["url", "https://example.test"])[0], 64)
        self.assertEqual(self.run_cli(["ssh", "me@host"])[0], 64)

    def test_exit_codes(self):
        self.assertEqual(report.exit_code([{"status": "patched"}]), 0)
        self.assertEqual(report.exit_code([{"status": "patched"}, {"status": "vulnerable"}]), 4)


if __name__ == "__main__":
    unittest.main()


class LocalTests(unittest.TestCase):
    def test_local_finds_fake_php(self):
        import os, stat, tempfile
        from php2shell_check.local_mode import run_local
        with tempfile.TemporaryDirectory() as d:
            exe = os.path.join(d, "php")
            with open(exe, "w") as f:
                f.write('#!/bin/sh\necho "PHP 8.3.30 (cli)"\n')
            os.chmod(exe, os.stat(exe).st_mode | stat.S_IEXEC)
            old = os.environ["PATH"]
            os.environ["PATH"] = d + os.pathsep + old
            try:
                inv = run_local()
            finally:
                os.environ["PATH"] = old
        hits = [r for r in inv.runtimes if r.path.endswith("/php") and r.version == (8, 3, 30)]
        self.assertTrue(hits)
        self.assertEqual(hits[0].verdict.status, "vulnerable")
