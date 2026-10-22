# php2shell-check

Check PHP runtime versions against the PHP2Shell fixes
([CVE-2026-109618 and CVE-2026-109619](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)).
Python 3.9 or newer, no third-party dependencies. Linux/POSIX host inventory.

This is a version and inventory checker, not an exploit or a webshell detector.
It does not prove a website is safe. Use remote modes only on systems you own
or have permission to inspect.

## Quick start

Clone the repo and run from its directory:

```sh
git clone https://github.com/hyderoo/php2shell-check.git
cd php2shell-check
python3 -m php2shell_check local
```

Other modes:

```sh
# Header hint only. A version header never earns a "patched" verdict.
python3 -m php2shell_check url https://example.com --i-am-authorized

# Inventory a host using your SSH key or agent.
python3 -m php2shell_check ssh deploy@host --identity ~/.ssh/id_ed25519 --i-am-authorized

# Search local logs for weak signals, not proof of exploitation.
python3 -m php2shell_check logs /var/log/apache2/error.log /var/log/php8.3-fpm.log

# Put the output option before the mode.
python3 -m php2shell_check --format json local
```

SSH requires the host key already in `known_hosts`. It uses strict host-key
checking and non-interactive authentication. Add `--known-hosts PATH` for a
separate file. No password prompt is provided.

## What gets checked

| Mode | Reads | Does not establish |
| --- | --- | --- |
| `local` | PHP binaries in PATH/common directories, versions, CLI ini values, installed packages, running container names and worker child shells | Which runtime serves HTTP, whether workers restarted, or what is inside each container |
| `ssh` | The same inventory, sent to `sh -s` over SSH | Anything outside that host's visibility |
| `url` | `X-Powered-By` and `Server` from one GET per URL, at most 20 URLs | A trusted runtime version, vendor backports, or patch state. Redirects are not followed |
| `logs` | Memory exhaustion at `Unknown on line 0`, segfault text and `PHP_SESSION_UPLOAD_PROGRESS` | That an attack happened, or that no attack happened when nothing matches |

The probe does not intentionally change files or settings. It runs local PHP
binaries to read their version/configuration; it is not a sandbox for untrusted
executables. Normal network and SSH access logs can still be written by services.
Log evidence and process arguments can contain sensitive data. Review output
before sharing it.

## Interpreting results

Upstream fixes: **8.2.35, 8.3.36, 8.4.27, 8.5.12**.
PHP 8.1 and older have no new upstream release for these fixes. Source backports
exist for 7.4, 8.0 and 8.1; check your vendor or move to a supported branch.

| Result | Meaning |
| --- | --- |
| `patched` | An inspected binary meets the upstream threshold, or its owning Ubuntu package meets Canonical's fixed version. Not a site-wide verdict |
| `vulnerable` | An inspected upstream build or verified Ubuntu package is below its fixed version |
| `review` | Header-only evidence, a possible vendor backport, an unsupported branch, a container not inspected, an installed Apache module, or a weak log/process signal |
| `unknown` | Not enough evidence to judge |
| `error` | A check failed or the inventory was incomplete |
| `note` | Configuration/context only. Does not change the verdict |

Exit codes: `0` patched (or no log signals), `1` error, `2` unknown,
`3` review, `4` vulnerable. Missing remote authorization or too many URLs returns
`64`; argparse syntax errors return `2`. For JSON log scans with no hits,
`overall` is `no-signals`, never `patched`.

When several findings exist, vulnerable/review findings take priority over
errors, then unknown, then patched. Check individual findings too.

## Vendor packages and blind spots

Ubuntu's fixed-package table covers 14.04 through 26.10, using
[Canonical's advisory](https://ubuntu.com/blog/php2shell-vulnerability-fixes-available).
The probe checks which installed package owns a binary before applying that
table. Sury/Ondrej/Remi builds are excluded. Other package origins cannot be
proved from version text alone; inspect repository provenance when in doubt.
Debian, RHEL and Alpine have no built-in fixed-package table.

Apache `mod_php` packages get a review finding. The tool does not inspect the
loaded module. Bundled runtimes, FrankenPHP, LiteSpeed and nested vendor
installation directories may be missed. Run it inside each container and check
the actual serving runtime separately. Config notes come from CLI PHP and can
differ from FPM or Apache configuration.

Restart or replace PHP workers after patching. A new binary on disk says
nothing about an old process still running. Configuration workarounds are not
a substitute for patching. Log and process checks are snapshots and have false
positives and false negatives.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Tests cover version boundaries, Ubuntu ownership and backports, command
construction, probe parsing, failure handling, JSON output and loopback HTTP
redirect behavior. CI runs Python 3.9 and 3.12 on Linux.

The original implementation was exercised against a local sshd and local HTTP
server. The audit used controlled fixtures and loopback HTTP, not an arbitrary
public website. No real PHP/FPM, Docker/Podman, Debian/RHEL/Alpine deployment or
production log corpus has been validated end to end. Passing tests are not a
claim of complete vulnerability coverage.

## Sources

- [PHP release announcement](https://www.php.net/releases/8_5_12.php)
- [Datadog: versions, mitigations and detection limits](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Ubuntu: fixed package versions](https://ubuntu.com/blog/php2shell-vulnerability-fixes-available)
