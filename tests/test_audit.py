"""Regression cases from the second audit. No internet targets required."""
import contextlib
import io
import json
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from php2shell_check import cli, report
from php2shell_check.local_mode import run_local
from php2shell_check.probe import parse_probe
from php2shell_check.ssh_mode import build_command, run_ssh
from php2shell_check.url_mode import check_url


class AuditTests(unittest.TestCase):
    def test_unrelated_package_cannot_patch_custom_binary(self):
        inv = parse_probe('@@os ubuntu 24.04\n@@bin /usr/bin/php-custom\nPHP 8.3.1 (cli)\n'
                          '@@pkg php8.3-common 8.3.6-0ubuntu0.24.04.13\n@@end\n')
        self.assertNotEqual(inv.runtimes[0].verdict.status, 'patched')

    def test_binary_owner_can_establish_ubuntu_backport(self):
        inv = parse_probe('@@os ubuntu 24.04\n@@bin /usr/bin/php8.3\n'
                          '@@owner php8.3-cli 8.3.6-0ubuntu0.24.04.13 installed\nPHP 8.3.6 (cli)\n@@end\n')
        self.assertEqual(inv.runtimes[0].verdict.status, 'patched')

    def test_php5_owner_matches_table(self):
        inv = parse_probe('@@os ubuntu 14.04\n@@bin /usr/bin/php5\n'
                          '@@owner php5-cli 5.5.9+dfsg-1ubuntu4.29+esm18 installed\nPHP 5.5.9 (cli)\n@@end\n')
        self.assertEqual(inv.runtimes[0].verdict.status, 'patched')

    def test_partial_inventory_never_overall_patched(self):
        rows = report.inventory_findings(parse_probe('@@bin /usr/local/bin/php\nPHP 8.5.12 (cli)\n'), 'h')
        self.assertEqual(report.worst(rows), 'error')
        self.assertEqual(report.exit_code(rows), 1)

    def test_apache_module_gets_a_finding(self):
        rows = report.inventory_findings(parse_probe('@@pkg libapache2-mod-php8.3 8.3.6-0ubuntu0.24.04.10\n@@end\n'), 'h')
        self.assertTrue(any('Apache PHP module' in r['reason'] for r in rows))

    def test_failed_probe_is_an_error(self):
        with patch('php2shell_check.local_mode.subprocess.run', return_value=subprocess.CompletedProcess([], 1, '@@end', 'failed')):
            with self.assertRaises(RuntimeError):
                run_local()
        with patch('php2shell_check.ssh_mode.subprocess.run', return_value=subprocess.CompletedProcess([], 1, '@@end', 'failed')):
            with self.assertRaises(RuntimeError):
                run_ssh('host')

    def test_timeout_is_caught_by_cli(self):
        with patch('php2shell_check.cli.run_local', side_effect=subprocess.TimeoutExpired('sh', 60)):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(['local']), 1)

    def test_empty_log_json_is_json(self):
        with tempfile.NamedTemporaryFile('w') as f:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(['--format', 'json', 'logs', f.name]), 0)
            self.assertEqual(json.loads(out.getvalue())['findings'], [])

    def test_invalid_port_and_timeout(self):
        for port in (0, -1, 65536):
            with self.assertRaises(ValueError):
                build_command('host', port)
        with self.assertRaises(ValueError):
            check_url('https://example.test', timeout=0)

    def test_redirect_stays_on_authorized_target(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(302)
                self.send_header('Location', '/outside-scope')
                self.end_headers()
            def log_message(self, *args):
                pass
        with HTTPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                finding = check_url(f'http://127.0.0.1:{server.server_port}/start')
                self.assertEqual(requests, ['/start'])
                self.assertEqual(finding['evidence']['http_status'], 302)
                self.assertNotEqual(finding['status'], 'patched')
            finally:
                server.shutdown()
                thread.join()
