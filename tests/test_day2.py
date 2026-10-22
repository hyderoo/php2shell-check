import os
import tempfile
import unittest

from php2shell_check import hardening, logscan, report
from php2shell_check.distro import compare_deb, ubuntu_verdict
from php2shell_check.probe import parse_probe
from php2shell_check import cli


class DebCompareTests(unittest.TestCase):
    def test_ordering(self):
        self.assertEqual(compare_deb("8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.28"), 0)
        self.assertEqual(compare_deb("8.1.2-1ubuntu2.27", "8.1.2-1ubuntu2.28"), -1)
        self.assertEqual(compare_deb("8.1.2-1ubuntu2.30", "8.1.2-1ubuntu2.28"), 1)
        self.assertEqual(compare_deb("8.1.2-1ubuntu2.9", "8.1.2-1ubuntu2.28"), -1)  # numeric, not text
        self.assertEqual(compare_deb("8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13"), -1)
        self.assertEqual(compare_deb("1:8.3.6-1", "8.3.6-9"), 1)  # epoch wins
        self.assertEqual(compare_deb("8.3.6~rc1-1", "8.3.6-1"), -1)  # tilde sorts first


class UbuntuTableTests(unittest.TestCase):
    def test_noble(self):
        self.assertEqual(ubuntu_verdict("24.04", "8.3", ["8.3.6-0ubuntu0.24.04.13"])[0], "patched")
        self.assertEqual(ubuntu_verdict("24.04", "8.3", ["8.3.6-0ubuntu0.24.04.12"])[0], "vulnerable")

    def test_lowest_package_decides(self):
        v = ubuntu_verdict("24.04", "8.3", ["8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.9"])
        self.assertEqual(v[0], "vulnerable")

    def test_ppa_and_wrong_branch_not_judged(self):
        self.assertIsNone(ubuntu_verdict("24.04", "8.3", ["8.3.30-1+ubuntu24.04.1+deb.sury.org+1"]))
        self.assertIsNone(ubuntu_verdict("24.04", "8.2", ["8.2.20-0ubuntu0.24.04.1"]))
        self.assertIsNone(ubuntu_verdict("99.04", "8.3", ["8.3.6-0ubuntu0.24.04.13"]))


def probe_text(os_line, banner, pkg, extra=""):
    return f"@@host h\n{os_line}\n@@bin /usr/bin/php8.3\n{banner}\n@@owner {pkg} installed\n@@pkg {pkg}\n{extra}@@end\n"


class ProbeDay2Tests(unittest.TestCase):
    def test_ubuntu_backport_is_patched(self):
        inv = parse_probe(probe_text("@@os ubuntu 24.04", "PHP 8.3.6 (cli)", "php8.3-cli 8.3.6-0ubuntu0.24.04.13"))
        self.assertEqual(inv.runtimes[0].verdict.status, "patched")
        self.assertIn("ubuntu.com", inv.runtimes[0].verdict.reason)

    def test_ubuntu_old_package_is_vulnerable(self):
        inv = parse_probe(probe_text("@@os ubuntu 24.04", "PHP 8.3.6 (cli)", "php8.3-cli 8.3.6-0ubuntu0.24.04.10"))
        self.assertEqual(inv.runtimes[0].verdict.status, "vulnerable")

    def test_debian_stays_review(self):
        inv = parse_probe(probe_text("@@os debian 12", "PHP 8.2.7 (cli)", "php8.2-cli 8.2.7-1~deb12u1"))
        self.assertEqual(inv.runtimes[0].verdict.status, "review")

    def test_containers_procs_and_notes(self):
        extra = ("@@container web nginx-php:8.2\n"
                 "@@proc 123 77 sh sh -c id <- php-fpm8.3\n@@ini upload_progress=1\n")
        inv = parse_probe(probe_text("@@os ubuntu 24.04", "PHP 8.3.6 (cli)", "php8.3-cli 8.3.6-0ubuntu0.24.04.13", extra))
        rows = report.inventory_findings(inv, "h")
        reasons = " ".join(r["reason"] for r in rows)
        self.assertIn("container not inspected", reasons)
        self.assertIn("shell spawned by a web worker", reasons)
        # container and process rows must pull the overall result off "patched"
        self.assertEqual(report.worst(rows), "review")

    def test_notes_do_not_change_overall(self):
        inv = parse_probe("@@host h\n@@bin /usr/local/bin/php\nPHP 8.5.12 (cli)\n@@ini upload_progress=1\n@@end\n")
        rows = report.inventory_findings(inv, "h")
        self.assertTrue(any(r["status"] == "note" for r in rows))
        self.assertEqual(report.worst(rows), "patched")


class HardeningTests(unittest.TestCase):
    def test_notes(self):
        n = hardening.notes({"upload_progress": "1", "fatal_error_backtraces": "1", "memory_limit": "128M"}, (8, 5, 11))
        self.assertEqual(len(n), 3)
        self.assertEqual(hardening.notes({"upload_progress": "0"}, (8, 3, 1)), [])


class LogScanTests(unittest.TestCase):
    LINES = [
        "[Thu Oct 22 10:00:00 2026] [php:error] PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted (tried to allocate 40 bytes) in Unknown on line 0\n",
        "[core:notice] AH00052: child pid 99 exit signal Segmentation fault (11)\n",
        "GET /index.php?PHP_SESSION_UPLOAD_PROGRESS=x HTTP/1.1 200\n",
        "normal request line\n",
        "PHP Fatal error: Allowed memory size of 134217728 bytes exhausted in /var/www/app.php on line 12\n",
    ]

    def test_hits(self):
        hits = logscan.scan_lines(self.LINES, "t.log")
        names = [h["reason"].split(":")[0] for h in hits]
        self.assertEqual(names, ["memory-exhausted-during-init", "worker-segfault", "upload-progress-field"])
        self.assertTrue(all(h["status"] == "review" for h in hits))  # never "vulnerable"

    def test_ordinary_memory_error_with_file_location_ignored(self):
        self.assertEqual(logscan.scan_lines([self.LINES[4]]), [])

    def test_hit_cap(self):
        hits = logscan.scan_lines([self.LINES[1]] * 50)
        self.assertEqual(len(hits), logscan.MAX_HITS_PER_RULE + 1)

    def test_cli_logs(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.writelines(self.LINES)
        try:
            self.assertEqual(cli.main(["logs", f.name]), 3)
        finally:
            os.unlink(f.name)
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("all quiet\n")
        try:
            self.assertEqual(cli.main(["logs", f.name]), 0)
        finally:
            os.unlink(f.name)
        self.assertEqual(cli.main(["logs", "/nonexistent/file.log"]), 1)


if __name__ == "__main__":
    unittest.main()


class ShellProbeTests(unittest.TestCase):
    """Run the real probe script with fake `ps` and `docker` on PATH."""

    def test_probe_sees_worker_shell_and_container(self):
        import stat
        from php2shell_check.local_mode import run_local
        with tempfile.TemporaryDirectory() as d:
            def fake(name, body):
                path = os.path.join(d, name)
                with open(path, "w") as f:
                    f.write("#!/bin/sh\n" + body)
                os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
            fake("ps", 'echo "  100   1 php-fpm8.3 php-fpm: master"\n'
                       'echo "  101 100 sh sh -c id"\n'
                       'echo "  200   1 bash bash"\n'
                       'echo "  201 200 sh sh -c ls"\n')
            fake("docker", 'echo "@@container web nginx-php:8.2"\n')
            old = os.environ["PATH"]
            os.environ["PATH"] = d + os.pathsep + old
            try:
                inv = run_local()
            finally:
                os.environ["PATH"] = old
        self.assertEqual(len(inv.procs), 1)          # only the shell under php-fpm
        self.assertIn("php-fpm8.3", inv.procs[0])
        self.assertEqual(inv.containers, ["web nginx-php:8.2"])
