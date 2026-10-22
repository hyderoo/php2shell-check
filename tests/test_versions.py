import unittest
from php2shell_check.versions import parse, assess


class VersionTests(unittest.TestCase):
    def test_boundaries(self):
        cases = {(8, 5, 11): "vulnerable", (8, 5, 12): "patched", (8, 4, 26): "vulnerable",
                 (8, 4, 27): "patched", (8, 3, 35): "vulnerable", (8, 3, 36): "patched",
                 (8, 2, 34): "vulnerable", (8, 2, 35): "patched", (8, 2, 40): "patched"}
        for v, want in cases.items():
            self.assertEqual(assess(v).status, want, v)

    def test_eol_needs_review(self):
        for v in [(8, 1, 30), (8, 0, 1), (7, 4, 33), (5, 6, 40)]:
            self.assertEqual(assess(v).status, "review", v)

    def test_distro_low_version_is_review_not_vulnerable(self):
        self.assertEqual(assess((8, 3, 6), distro_build=True).status, "review")

    def test_unknown(self):
        self.assertEqual(assess(None).status, "unknown")

    def test_parse(self):
        self.assertEqual(parse("PHP 8.3.6 (cli) (built: Jan 1 2026)"), (8, 3, 6))
        self.assertIsNone(parse("no version here"))
        self.assertEqual(parse("nginx/1.25.3 PHP/8.4.27"), (1, 25, 3))  # first match wins, callers slice first
