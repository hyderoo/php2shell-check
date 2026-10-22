# php2shell-check

A small read-only checker for the PHP2Shell bugs, CVE-2026-109618 and CVE-2026-109619.
Both are unauthenticated RCEs in the PHP runtime itself, so the question that matters is
"which PHP is actually serving requests, and is it patched?" This tool answers that in
three ways. Python 3.9+, standard library only.

This is a defensive version check. It contains no exploit code and sends no attack traffic.
Run `url` and `ssh` only against systems you own or are allowed to test.

Fixed upstream releases: **8.2.35, 8.3.36, 8.4.27, 8.5.12**. PHP 8.1 and older get no
upstream release. Patching is the real fix; config flags only reduce exposure.

## Run it

```
python -m php2shell_check local
python -m php2shell_check url https://example.com https://example.com/app/ --i-am-authorized
python -m php2shell_check ssh deploy@host --identity ~/.ssh/id_ed25519 --i-am-authorized
python -m php2shell_check --format json local
```

| Mode | What it does |
|------|--------------|
| `local` | Finds `php`, `php-fpm`, `php-cgi` in PATH and common dirs, reads `-v`, two ini values, and installed php packages. |
| `url` | One plain GET per URL. Reads `X-Powered-By` / `Server`. No POST, no payloads, max 20 URLs. |
| `ssh` | Pipes the same inventory script to `sh -s` on the host. `StrictHostKeyChecking=yes` and `BatchMode`, so the host must already be in `known_hosts` and auth is your key or agent. It never takes a password. |

`url` and `ssh` refuse to run without `--i-am-authorized`. Only point them at things you own
or have permission to check.

Exit codes: `0` patched, `2` unknown, `3` needs review, `4` vulnerable, `64` bad usage, `1` error.

## Reading the result

- `vulnerable`: a plain upstream build below the fixed release.
- `review`: a distro package below the upstream number (vendors backport fixes without bumping
  the version), an end-of-life branch, or a version read from an HTTP header. Check the vendor advisory.
- `unknown`: nothing to judge. Not a clean bill of health.
- `patched`: at or above the fixed release. Restart your workers, a running old process stays vulnerable.

## Limits

- URL mode only sees what headers expose. Most hardened sites hide the version, so `unknown` is the common answer.
- It reports the version of binaries it finds. It cannot tell which one your web server actually runs,
  and it does not look inside containers or bundled interpreters. Run it inside each container or host.
- It does not detect exploitation or webshells already dropped on a host. For that, look at the
  indicators in the [Datadog write-up](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/).
- It does not try the exploit, by design.

## Develop

```
python -m unittest discover -s tests
```

Day 1 scope: version assessment and the three modes. Not done yet: container image scanning,
config-flag findings (`session.upload_progress.enabled`), a distro-fix table.
