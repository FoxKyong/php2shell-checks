#!/bin/bash
# Read-only check: is every PHP runtime on this host patched against php2shell
# (CVE-2026-109618 / CVE-2026-109619), and do running processes use the patched code?
# Changes nothing. Run as root so /proc/<pid>/maps of all processes is readable.
#
# Usage: sudo bash php2shell-patch-check.sh 2>&1 | tee /tmp/php2shell-patch-check-$(hostname).txt
# Optional: EXTRA_PATHS="/data/app /srv/www" sudo bash php2shell-patch-check.sh

export LC_ALL=C
SEARCH_PATHS="/usr /opt /srv /usr/local ${EXTRA_PATHS:-}"
CVES="CVE-2026-109618 CVE-2026-109619"
# First fixed upstream release per supported branch (php.net, 2026-10-21)
FIXED_8_2=8.2.35; FIXED_8_3=8.3.36; FIXED_8_4=8.4.27; FIXED_8_5=8.5.12

problems=0; warnings=0
hr()   { printf '\n===== %s =====\n' "$1"; }
bad()  { echo "  [VULNERABLE] $*"; problems=$((problems+1)); }
warn() { echo "  [WARN] $*"; warnings=$((warnings+1)); }
ok()   { echo "  [OK] $*"; }

# ver_ge A B: true when version A >= B
ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

# Fix status of an upstream version: fixed / vulnerable / eol
upstream_status() {
    local v=$1 branch fixed
    branch=$(echo "$v" | cut -d. -f1,2)
    case "$branch" in
        8.2) fixed=$FIXED_8_2;; 8.3) fixed=$FIXED_8_3;;
        8.4) fixed=$FIXED_8_4;; 8.5) fixed=$FIXED_8_5;;
        8.6) echo fixed; return;;   # 8.6 RC4+ carries the fix; RCs are not for production anyway
        *)   echo eol; return;;
    esac
    ver_ge "$v" "$fixed" && echo fixed || echo vulnerable
}

# Does the distro package owning file $1 mention both CVEs in its changelog? (backports)
pkg_of() {
    if command -v dpkg >/dev/null 2>&1; then dpkg -S "$1" 2>/dev/null | head -1 | cut -d: -f1
    elif command -v rpm >/dev/null 2>&1; then rpm -qf "$1" 2>/dev/null | grep -v 'not owned' | head -1; fi
}
changelog_has_cves() {
    local pkg=$1 log="" c
    [ -n "$pkg" ] || return 1
    if command -v dpkg >/dev/null 2>&1; then
        for f in /usr/share/doc/"$pkg"/changelog.Debian.gz \
                 /usr/share/doc/$(echo "$pkg" | grep -oE 'php[0-9]+\.[0-9]+' | head -1)-common/changelog.Debian.gz; do
            [ -f "$f" ] && { log=$(zcat "$f" 2>/dev/null); break; }
        done
    elif command -v rpm >/dev/null 2>&1; then
        log=$(rpm -q --changelog "$pkg" 2>/dev/null)
    fi
    for c in $CVES; do echo "$log" | grep -q "$c" || return 1; done
    return 0
}

# Verdict for one runtime: path + "PHP x.y.z" version
judge() {
    local path=$1 v=$2 st pkg
    st=$(upstream_status "$v")
    pkg=$(pkg_of "$path")
    if [ "$st" = fixed ]; then
        ok "$path  PHP $v  (>= fixed upstream release)${pkg:+  pkg: $pkg}"
    elif changelog_has_cves "$pkg"; then
        ok "$path  PHP $v  (distro backport: changelog of $pkg lists both CVEs)"
    elif [ "$st" = eol ]; then
        bad "$path  PHP $v  - branch has no upstream fix and the package changelog does not list the CVEs${pkg:+ (pkg: $pkg)}"
    else
        bad "$path  PHP $v  - older than the fixed release of its branch${pkg:+ (pkg: $pkg)}"
    fi
}

hr "host"
hostname -f 2>/dev/null || hostname
grep -E '^(PRETTY_NAME)=' /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null
date -u '+checked %Y-%m-%d %H:%M UTC'
[ "$(id -u)" -eq 0 ] || echo "WARNING: not root - other users' processes are not visible, results incomplete"

hr "1. PHP binaries on disk ($SEARCH_PATHS)"
runtimes=0
while read -r f; do
    [ -n "$f" ] && [ -x "$f" ] && [ ! -d "$f" ] || continue
    v=$(timeout 5 "$f" -v 2>/dev/null | head -1 | grep -oE '^PHP [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2)
    [ -n "$v" ] || continue
    runtimes=$((runtimes+1)); judge "$f" "$v"
done < <(for d in $SEARCH_PATHS; do [ -d "$d" ] && timeout 120 find "$d" -xdev \
            \( -name 'php' -o -name 'php[0-9]*' -o -name 'php-cgi*' -o -name 'php-fpm*' -o -name 'lsphp*' -o -name 'frankenphp' \) \
            -type f 2>/dev/null; done | sort -u)
[ "$runtimes" -gt 0 ] || echo "  no PHP binaries found"

hr "2. running processes: do they use the patched code? (restart check)"
# A package upgrade replaces files on disk; a process started before it keeps the old
# inode, which /proc shows as "(deleted)". Such a process still runs the vulnerable code.
seen=0; out=""
for d in /proc/[0-9]*; do
    exe=$(readlink "$d/exe" 2>/dev/null) || continue
    comm=$(cat "$d/comm" 2>/dev/null)
    lib=$(grep -m1 -oE '/[^ ]*(libphp[^ ]*\.so|mod_php[^ ]*\.so)( \(deleted\))?$' "$d/maps" 2>/dev/null)
    case "$comm" in php*|lsphp*|frankenphp) ;; *) [ -n "$lib" ] || continue;; esac
    seen=$((seen+1))
    if [[ "$exe" == *" (deleted)" ]]; then
        out+="  [VULNERABLE] $comm runs a binary replaced on disk: $exe -> restart the service"$'\n'
    elif [[ "$lib" == *" (deleted)" ]]; then
        out+="  [VULNERABLE] $comm has a replaced PHP module loaded: $lib -> restart the web server"$'\n'
    elif grep -qE 'php.* \(deleted\)$' "$d/maps" 2>/dev/null; then
        out+="  [VULNERABLE] $comm ($exe) still maps deleted PHP files -> restart the service"$'\n'
    else
        out+="  [OK] $comm ${lib:-$exe}  (no replaced PHP files in memory)"$'\n'
    fi
done
if [ "$seen" -gt 0 ]; then
    printf '%s' "$out" | sort | uniq -c | sed -E 's/^ *([0-9]+) (.*)/\2  [x\1 processes]/'
    problems=$((problems + $(printf '%s' "$out" | grep -c VULNERABLE)))
else
    echo "  no running process uses PHP"
fi

hr "3. running PHP version vs. installed (php-fpm / mod_php)"
for d in /proc/[0-9]*; do
    exe=$(readlink "$d/exe" 2>/dev/null) || continue
    case "$(cat "$d/comm" 2>/dev/null)" in php-fpm*) echo "$exe";; esac
done | sort -u | while read -r e; do
    e=${e% (deleted)}
    [ -x "$e" ] && echo "  php-fpm binary $e reports: $($e -v 2>/dev/null | head -1)"
done
for d in /proc/[0-9]*; do grep -m1 -oE '/[^ ]*libphp[^ ]*\.so' "$d/maps" 2>/dev/null; done | sort -u | while read -r l; do
    p=$(pkg_of "$l")
    if [ -n "$p" ]; then
        if command -v dpkg >/dev/null 2>&1; then pv=$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null); else pv=$(rpm -q "$p" 2>/dev/null); fi
        echo "  mod_php module $l from package $p $pv"
        changelog_has_cves "$p" && echo "    changelog lists both CVEs" || echo "    changelog does not list the CVEs - check the version against the fixed release"
    else
        echo "  mod_php module $l (not owned by a package - check its build)"
    fi
done

hr "4. session.upload_progress.enabled (CVE-2026-115560: PHP advises Off until the next release)"
for f in $(ls /etc/php/*/*/php.ini /etc/php.ini /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf 2>/dev/null); do
    val=$(grep -iE '^\s*(php_admin_flag\[)?session\.upload_progress\.enabled' "$f" 2>/dev/null | tail -1)
    echo "  $f: ${val:-not set (default On)}"
done
for e in $(ls /usr/bin/php[0-9]* /usr/bin/php 2>/dev/null | sort -u); do
    v=$(timeout 5 "$e" -r 'echo ini_get("session.upload_progress.enabled") ? "On" : "Off";' 2>/dev/null)
    [ -n "$v" ] && echo "  CLI $e (cli php.ini only - FPM/Apache use the files listed above): $v"
done
echo "  note: only exploitable when an app switches session.serialize_handler at runtime (php.net, 2026-10-23); Off is the recommended setting"

hr "5. containers"
for rt in docker podman; do
    command -v $rt >/dev/null 2>&1 || continue
    for c in $($rt ps --format '{{.Names}}' 2>/dev/null); do
        v=$($rt exec "$c" sh -c 'php -v 2>/dev/null | head -1' 2>/dev/null | grep -oE '^PHP [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2)
        [ -n "$v" ] || continue
        st=$(upstream_status "$v")
        if [ "$st" = fixed ]; then ok "[$rt:$c] PHP $v"; else bad "[$rt:$c] PHP $v ($st) - rebuild/pull the image and recreate the container"; fi
    done
done
echo "  (end of container list)"

hr "VERDICT"
if [ "$problems" -gt 0 ]; then
    echo "NOT FIXED: $problems problem(s) above marked [VULNERABLE]"
elif [ "$runtimes" -eq 0 ] && [ "$seen" -eq 0 ]; then
    echo "no PHP on this host"
else
    echo "FIXED: every PHP runtime found is patched and no running process uses replaced PHP files"
fi
