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
python -m php2shell_check logs /var/log/apache2/error.log /var/log/php8.3-fpm.log
python -m php2shell_check --format json local
```

| Mode | What it does |
|------|--------------|
| `local` | Finds `php`, `php-fpm`, `php-cgi` in PATH and common dirs, reads `-v`, three ini values, installed php packages, the OS, running containers, and shells spawned by web workers. |
| `url` | One plain GET per URL. Reads `X-Powered-By` / `Server`. No POST, no payloads, max 20 URLs. |
| `ssh` | Pipes the same inventory script to `sh -s` on the host. `StrictHostKeyChecking=yes` and `BatchMode`, so the host must already be in `known_hosts` and auth is your key or agent. It never takes a password. |
| `logs` | Greps local log files for the weak signals Datadog describes: memory exhaustion at "Unknown on line 0", worker segfaults, `PHP_SESSION_UPLOAD_PROGRESS` in request text. |

`url` and `ssh` refuse to run without `--i-am-authorized`. Only point them at things you own
or have permission to check. Everything it runs on a host is a version query, `ps`, `docker ps`
and package listing. It writes nothing.

Exit codes: `0` patched / nothing found, `2` unknown, `3` needs review, `4` vulnerable, `64` bad usage, `1` error.

## Reading the result

- `vulnerable`: a plain upstream build below the fixed release, or an Ubuntu package below Canonical's fixed version.
- `review`: a distro package below the upstream number on a distro we have no cited table for
  (vendors backport fixes without bumping the version), an end-of-life branch, a version read from an HTTP header,
  a running container, a shell under a web worker, or a log hit. Look at it by hand.
- `unknown`: nothing to judge. Not a clean bill of health.
- `patched`: at or above the fixed release. Restart your workers, a running old process stays vulnerable.
- `note`: config observations (`session.upload_progress.enabled`, `fatal_error_backtraces`, `memory_limit`).
  These never change the verdict. Only patching fixes the bugs.

Distro fix versions are only built in for Ubuntu, from
[Canonical's advisory](https://ubuntu.com/blog/php2shell-vulnerability-fixes-available).
Ubuntu packages from a PPA (Sury, Ondrej) are not judged by that table. Debian, RHEL, Alpine and others stay `review`
until a cited source is added to `php2shell_check/distro.py`.

## Limits

- URL mode only sees what headers expose. Most hardened sites hide the version, so `unknown` is the common answer, and it never means safe.
- It reports the binaries it finds. It cannot tell which one your web server runs. Containers are listed, not
  looked into: run the tool inside each one. Bundled interpreters (FrankenPHP, Docker images without `php` in PATH) can be missed.
- The log scan and the worker-shell check are weak signals. Legitimate apps run shells and hit memory limits.
  No hit does not mean no attack, since the exploit does not need to crash a worker.
- It does not look for dropped webshells and does not try the exploit, by design.
- Tested live over SSH against a local sshd and against a local HTTP server. Not tested against real Debian, RHEL or Alpine hosts.

## Develop

```
python -m unittest discover -s tests
```

Sources for the fixed versions and detection signals:
[Datadog Security Labs](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/),
[Vercel bulletin](https://vercel.com/kb/bulletin/php2shell-security-bulletin),
[PHP 8.5.12 release](https://www.php.net/releases/8_5_12.php).
