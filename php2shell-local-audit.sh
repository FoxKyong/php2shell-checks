#!/usr/bin/env bash
# php2shell-local-audit.sh — read-only PHP2Shell (CVE-2026-109618 / -109619)
# exposure audit for a host you can log into. It changes nothing: it only reads
# versions and process state. It is the authoritative check for PHP that lives
# in Docker images or appliances, where a network probe cannot see the real
# build or tell whether the running worker was restarted onto the fixed binary.
#
# Usage:  bash php2shell-local-audit.sh
#         sudo bash php2shell-local-audit.sh      # to also read other users' /proc and docker
#
# It reports, per PHP it finds:
#   - the version and whether it is at/above the fixed patch level
#   - for running php-fpm / apache workers: whether the binary on disk was
#     replaced after the process started (i.e. an upgrade that was NOT restarted)
#   - PHP inside each running Docker container, and the container's image
set -u

# Fixed upstream patch level per branch (PHP security release 2026-10-21).
# A distro backport can be fixed at a LOWER number, so a below-fix result on a
# distribution build means "verify with the package manager", not "vulnerable".
fixed_for() { # major.minor -> fixed patch, or empty if branch has no upstream fix
  case "$1" in
    8.2) echo 35 ;; 8.3) echo 36 ;; 8.4) echo 27 ;; 8.5) echo 12 ;;
    *) echo "" ;;
  esac
}

# Branches PHP never fixed upstream. A branch that is neither here nor in
# fixed_for() is newer than this tool knows (e.g. a future 8.6/9.0) -> UNKNOWN,
# never a confident "end-of-life vulnerable".
is_eol_branch() {
  case "$1" in
    5.3|5.4|5.5|5.6|7.0|7.1|7.2|7.3|7.4|8.0|8.1) return 0 ;;
    *) return 1 ;;
  esac
}

C_RED=$'\033[91m'; C_GRN=$'\033[92m'; C_YEL=$'\033[93m'; C_CYN=$'\033[96m'; C_RST=$'\033[0m'
[ -t 1 ] || { C_RED=; C_GRN=; C_YEL=; C_CYN=; C_RST=; }

verdict_for_version() { # full version string like 8.3.6-0ubuntu... -> prints verdict
  local v="$1" mm patch fixed suffix
  mm=$(printf '%s' "$v" | sed -nE 's/^([0-9]+\.[0-9]+)\..*/\1/p')
  patch=$(printf '%s' "$v" | sed -nE 's/^[0-9]+\.[0-9]+\.([0-9]+).*/\1/p')
  suffix=$(printf '%s' "$v" | sed -nE 's/^[0-9]+\.[0-9]+\.[0-9]+(.*)$/\1/p')
  [ -z "$mm" ] && { printf '%s' "${C_YEL}UNKNOWN (unparsable)${C_RST}"; return; }
  local has_suffix=0
  printf '%s' "$suffix" | grep -qE '[-+~]|\.(el[0-9]|fc[0-9]|deb|ubuntu|amzn|alpine|mga)' && has_suffix=1
  fixed=$(fixed_for "$mm")
  if [ -n "$fixed" ]; then
    # Supported branch: at/above the fix is patched regardless of any suffix.
    if [ "${patch:-0}" -ge "$fixed" ]; then
      printf '%s' "${C_GRN}FIXED (>= ${mm}.${fixed})${C_RST}"; return
    fi
    if [ "$has_suffix" = 1 ]; then
      printf '%s' "${C_YEL}DISTRO BUILD < fix — check package (suffix: ${suffix})${C_RST}"; return
    fi
    printf '%s' "${C_RED}VULNERABLE (< ${mm}.${fixed}) — if a distro package, may be backported; verify${C_RST}"; return
  fi
  # Branch with no upstream fix.
  if [ "$has_suffix" = 1 ]; then
    printf '%s' "${C_YEL}EOL DISTRO BUILD — check package (suffix: ${suffix})${C_RST}"; return
  fi
  if is_eol_branch "$mm"; then
    printf '%s' "${C_RED}VULNERABLE — end-of-life branch, no upstream fix${C_RST}"; return
  fi
  printf '%s' "${C_YEL}UNKNOWN — branch newer than this tool; check advisory${C_RST}"
}

section() { printf '\n%s== %s ==%s\n' "$C_CYN" "$1" "$C_RST"; }

section "PHP on the host filesystem"
found=0
declare -A seen_bin=()
for bin in php php7 php8 php-cgi php-fpm php-fpm8.2 php-fpm8.3 php-fpm8.4 php-fpm8.5; do
  for p in $(command -v "$bin" 2>/dev/null; compgen -c "$bin" 2>/dev/null); do
    path=$(command -v "$p" 2>/dev/null) || continue
    # Resolve and deduplicate: the same binary matches several prefixes above.
    real=$(readlink -f "$path" 2>/dev/null || printf '%s' "$path")
    [ -n "${seen_bin[$real]:-}" ] && continue
    seen_bin[$real]=1
    ver=$("$path" --version 2>/dev/null | sed -nE 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+[^ ]*).*/\1/p' | head -1)
    [ -z "$ver" ] && continue
    found=1
    printf '%s\n    %s -> %s\n' "$path" "$ver" "$(verdict_for_version "$ver")"
  done
done
[ "$found" = 0 ] && echo "  (no PHP CLI/FPM binary found on the host filesystem)"

section "Running PHP workers — restarted after an upgrade, and what version?"
# A process whose /proc/<pid>/exe points at a '(deleted)' inode is still running
# the OLD binary even though the package was updated. Those must be restarted.
# We also version-check each running PHP binary directly, which catches PHP that
# lives off PATH (e.g. bundled in a snap at /snap/<app>/<rev>/bin/php-fpm).
any=0
declare -A php_bins=()
for pid in $(pgrep -f 'php-fpm|php-cgi|apache2|httpd' 2>/dev/null); do
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
  case "$exe" in *php*|*apache2*|*httpd*) : ;; *) continue ;; esac
  any=1
  clean=${exe% (deleted)}
  if printf '%s' "$exe" | grep -q '(deleted)'; then
    printf '  %spid %s: %s  <- running a REPLACED binary; restart this service%s\n' \
      "$C_RED" "$pid" "$exe" "$C_RST"
  elif grep -q 'libphp.*(deleted)' "/proc/$pid/maps" 2>/dev/null; then
    printf '  %spid %s (%s): mod_php .so replaced on disk; restart Apache%s\n' \
      "$C_RED" "$pid" "$exe" "$C_RST"
  else
    printf '  %spid %s: %s (binary current)%s\n' "$C_GRN" "$pid" "$exe" "$C_RST"
  fi
  case "$clean" in *php*) php_bins[$clean]=1 ;; esac
done
[ "$any" = 0 ] && echo "  (no running php-fpm/apache workers visible — try with sudo)"
if [ "${#php_bins[@]}" -gt 0 ]; then
  echo
  echo "  version of each running PHP binary:"
  for bin in "${!php_bins[@]}"; do
    ver=$("$bin" --version 2>/dev/null | sed -nE 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+[^ ]*).*/\1/p' | head -1)
    note=""
    # Fallback for binaries that will not execute standalone (snap/bundled libs):
    # read the version literal out of the binary's strings. Best-effort only —
    # a bundled library (e.g. curl 8.x) can share the shape, so flag it to verify.
    if [ -z "$ver" ] && command -v strings >/dev/null 2>&1; then
      ver=$(strings -a "$bin" 2>/dev/null \
            | grep -aoE '\b[578]\.[0-9]+\.[0-9]+\b' \
            | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')
      [ -n "$ver" ] && note="   ${C_YEL}(read from binary strings — verify in the app admin UI)${C_RST}"
    fi
    if [ -n "$ver" ]; then
      printf '    %s\n      %s -> %s%s\n' "$bin" "$ver" "$(verdict_for_version "$ver")" "$note"
    else
      printf '    %s\n      %scould not read version — check the app admin UI (e.g. Nextcloud: Administration > System > PHP)%s\n' \
        "$bin" "$C_YEL" "$C_RST"
    fi
  done
fi

section "PHP inside running Docker containers"
if command -v docker >/dev/null 2>&1; then
  if ! docker ps >/dev/null 2>&1; then
    echo "  (cannot talk to the Docker daemon — try with sudo)"
  else
    docker ps --format '{{.ID}} {{.Names}} {{.Image}}' | while read -r id name image; do
      # __NOPHP__ lets us tell "shell ran, PHP absent" from "exec itself failed"
      # (distroless image with no shell, exec disabled, container restarting).
      out=$(docker exec "$id" sh -c \
        'php -v 2>/dev/null || php-fpm -v 2>/dev/null || echo __NOPHP__' 2>/dev/null)
      rc=$?
      ver=$(printf '%s' "$out" | sed -nE 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+[^ ]*).*/\1/p' | head -1)
      if [ -n "$ver" ]; then
        printf '  %-20s image=%s\n      %s -> %s\n' "$name" "$image" "$ver" "$(verdict_for_version "$ver")"
      elif [ "$rc" -ne 0 ] || [ -z "$out" ]; then
        printf '  %-20s image=%s  %scould not run php -v (no shell / exec disabled / restarting?) — check the image tag%s\n' \
          "$name" "$image" "$C_YEL" "$C_RST"
      else
        printf '  %-20s image=%s  no PHP binary in container\n' "$name" "$image"
      fi
    done
  fi
else
  echo "  (docker CLI not present on this host)"
fi

cat <<EOF

${C_CYN}How to read this${C_RST}
  FIXED              at/above the upstream fixed patch level.
  VULNERABLE         below the fix, or an end-of-life branch with no upstream fix.
  DISTRO BUILD       distro revision suffix present; the patch number is not
                     authoritative. Confirm with the package manager, e.g.
                     dpkg -l 'php*' / rpm -q php / apk info -v php*.
  REPLACED binary    the package was updated but the worker still runs the old
                     code in memory. It stays vulnerable until the service is
                     restarted.

A clean result here is only as current as the moment you ran it. Re-run after
any PHP or image update, and restart the workers.
EOF
