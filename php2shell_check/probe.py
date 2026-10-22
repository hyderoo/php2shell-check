"""Read-only inventory script, shared by local and SSH modes.

It only runs `php -v` style version queries, reads two ini values and lists
installed php packages. It writes nothing and never touches web content.
"""
import re
from dataclasses import dataclass, field

from .versions import parse, assess, Verdict
from .distro import ubuntu_verdict

PROBE_SCRIPT = r"""
set -u
echo "@@host $(hostname 2>/dev/null)"
if [ -r /etc/os-release ]; then
  . /etc/os-release 2>/dev/null
  echo "@@os ${ID:-unknown} ${VERSION_ID:-unknown}"
fi
[ -f /.dockerenv ] && echo "@@incontainer yes"
seen=""
for dir in $(echo "$PATH" | tr ':' ' ') /usr/local/bin /usr/sbin /opt/remi /opt/plesk/php; do
  for bin in "$dir"/php "$dir"/php[0-9]* "$dir"/php-fpm* "$dir"/php-cgi*; do
    [ -x "$bin" ] && [ -f "$bin" ] || continue
    real=$(readlink -f "$bin" 2>/dev/null || echo "$bin")
    case " $seen " in *" $real "*) continue;; esac
    seen="$seen $real"
    echo "@@bin $real"
    if command -v dpkg-query >/dev/null 2>&1; then
      dpkg-query -S "$real" 2>/dev/null | while IFS= read -r owner; do
        pkg=${owner%%: /*}
        dpkg-query -W -f='@@owner ${Package} ${Version} ${db:Status-Status}\n' "$pkg" 2>/dev/null
      done
    elif command -v rpm >/dev/null 2>&1; then
      rpm -qf --qf '@@owner %{NAME} %{VERSION}-%{RELEASE} installed\n' "$real" 2>/dev/null
    fi
    "$real" -v 2>/dev/null | head -n 1
    case "$real" in
      *fpm*|*cgi*) ;;
      *) echo "@@ini upload_progress=$("$real" -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null)"
         echo "@@ini memory_limit=$("$real" -r 'echo ini_get("memory_limit");' 2>/dev/null)"
         echo "@@ini fatal_error_backtraces=$("$real" -r 'echo ini_get("fatal_error_backtraces");' 2>/dev/null)";;
    esac
  done
done
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${db:Status-Status} @@pkg ${Package} ${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | sed -n 's/^installed //p'
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa 'php*' 'libapache2-mod-php*' 2>/dev/null | sed 's/^/@@pkg /'
fi
for rt in docker podman; do
  if command -v $rt >/dev/null 2>&1; then
    $rt ps --format '@@container {{.Names}} {{.Image}}' 2>/dev/null
  fi
done
ps -eo pid=,ppid=,comm=,args= 2>/dev/null | awk '
  { c[$1]=$3; par[$1]=$2; line[$1]=$0 }
  END { for (p in par)
    if (c[p] ~ /^(sh|bash|dash|zsh)$/ && c[par[p]] ~ /^(php|lsphp|frankenphp|apache2|httpd)/)
      print "@@proc " line[p] " <- " c[par[p]] }'
echo "@@end"
"""


@dataclass
class Runtime:
    path: str
    banner: str = ""
    version: tuple = None
    ini: dict = field(default_factory=dict)
    verdict: Verdict = None
    distro: bool = False
    owners: list = field(default_factory=list)


@dataclass
class Inventory:
    host: str = ""
    runtimes: list = field(default_factory=list)
    packages: list = field(default_factory=list)
    os: tuple = ("unknown", "unknown")
    in_container: bool = False
    containers: list = field(default_factory=list)
    procs: list = field(default_factory=list)
    complete: bool = False


def parse_probe(output):
    inv = Inventory()
    cur = None
    for line in output.splitlines():
        if line.startswith("@@host "):
            inv.host = line[7:].strip()
        elif line.startswith("@@bin "):
            cur = Runtime(path=line[6:].strip())
            inv.runtimes.append(cur)
        elif line.startswith("@@owner ") and cur:
            parts = line[8:].split()
            if len(parts) == 3 and parts[2] == "installed":
                cur.owners.append((parts[0], parts[1]))
        elif line.startswith("@@ini ") and cur:
            k, _, v = line[6:].partition("=")
            cur.ini[k.strip()] = v.strip()
        elif line.startswith("@@pkg "):
            inv.packages.append(line[6:].strip())
        elif line.startswith("@@os "):
            parts = line[5:].split()
            inv.os = (parts[0], parts[1]) if len(parts) >= 2 else inv.os
        elif line.startswith("@@incontainer"):
            inv.in_container = True
        elif line.startswith("@@container "):
            inv.containers.append(line[12:].strip())
        elif line.startswith("@@proc "):
            inv.procs.append(line[7:].strip())
        elif line.startswith("@@end"):
            inv.complete = True
        elif cur and not cur.banner and line.strip():
            cur.banner = line.strip()
    for rt in inv.runtimes:
        rt.version = parse(rt.banner)
        # Package presence alone does not establish who built this binary.
        rt.distro = bool(rt.owners) or bool(re.search(r"ubuntu|debian|el\d|fc\d", rt.banner.lower()))
        rt.verdict = assess(rt.version, distro_build=rt.distro)
        if rt.owners and rt.version and inv.os[0] == "ubuntu":
            branch = f"{rt.version[0]}.{rt.version[1]}"
            base = "php5" if rt.version[0] == 5 else f"php{branch}"
            vers = [v for name, v in rt.owners if name == base or name.startswith(base + "-")]
            hit = ubuntu_verdict(inv.os[1], branch, vers)
            if hit:
                rt.verdict = Verdict(*hit)
    return inv
