# PHP2Shell exposure checks (CVE-2026-109618 / CVE-2026-109619)

Tooling to check hosts for exposure to **PHP2Shell**, the two critical
unauthenticated-RCE flaws in the PHP interpreter disclosed on 2026-10-21:

- **CVE-2026-109618** — RCE via out-of-memory corruption during request cleanup.
- **CVE-2026-109619** — RCE via stale request-owned global state (use-after-free).

Both are fixed upstream in **PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**. Branches
8.1 and older get no upstream fix (some distributions/LTS vendors backport; PHP
published source-only backports for 7.4 / 8.0 / 8.1). Both CVEs are in the CISA
KEV catalog (added 2026-10-26) — treat them as actively exploited.

Three complementary tools, because "no system access", "access but PHP is
bundled (Docker/snap)" and "did the patched build actually get loaded" need
different methods:

| Tool | Where it runs | Answers |
|---|---|---|
| `php2shell-scanner.py` | over the network | is a reachable endpoint crashable / what version does it advertise |
| `php2shell-local-audit.sh` | on the box | which PHP builds exist, incl. off-PATH / Docker, and were workers restarted |
| `php2shell-patch-check.sh` | on the box | is every runtime at/above the fix (changelog-aware) and is the stopgap set |

The two on-box scripts overlap on purpose (both do the version and restart
checks) but lead in different areas — see each section. Running both, or just
the one whose strengths match the host, is fine.

## `php2shell-scanner.py` — network scanner

An accuracy-hardened fork of
[`assetnote/php2shell-scanner`](https://github.com/assetnote/php2shell-scanner).
**Only the result-interpretation layer was changed; the probe payloads and the
crash primitive are untouched on purpose** — the goal is more accurate
*detection*, not a more effective exploit.

**Scope of the active check.** The crash probe exercises the
**CVE-2026-109618** OOM path only: a `VULNERABLE` verdict is a real,
crash-confirmed OOM-corruption finding. **CVE-2026-109619** (stale global
state) is *not* actively probed — reproducing it needs two requests landing on
the same worker and is far more disruptive — so for 109619 this tool relies on
the advertised version alone. A host that is crash-clean but on an unpatched
version is therefore still exposed to 109619; confirm the build on the box.

What changed vs. upstream:

- **Confident `VULNERABLE` only from a real crash** (and only for 109618, per
  the scope note above). A below-fix version with no crash is reported
  `LIKELY_VULNERABLE` (verify), never a hard positive.
- **Distribution backport awareness.** A version with a distro revision suffix
  (e.g. `8.3.6-0ubuntu0.24.04.13`) is `INCONCLUSIVE` ("check the package"),
  not a false `VULNERABLE`/`FIXED`.
- **End-of-life branches** (7.x, 8.0, 8.1) with no backport → flagged, not
  silently treated as clean. Branches newer than the tool knows → `UNKNOWN`.
- **Uncertain never folds into "safe."** Hidden version + no crash → `UNKNOWN`.
- **Version read from `X-Powered-By` and `Server`.**
- **Same-host redirect following** (http→https, `/`→entry point); `303 See
  Other` is not followed (the POST was already processed) and cross-host
  redirects are reported, never chased.

```
.venv/bin/python php2shell-scanner.py -u https://example.com -v
.venv/bin/python php2shell-scanner.py -u https://example.com --path /auth/login
.venv/bin/python php2shell-scanner.py -l hosts.txt -o results.json
```

Exit codes (for CI): `0` clean · `5` inconclusive/unknown · `10` likely
(verify) · `20` confirmed by crash · `3` output write error · `2` usage error.
Only a crash yields `20`.

> The active probe deliberately triggers an OOM to detect the flaw and can crash
> a worker. Run it only against hosts you own or are authorized to test, and
> prefer off-peak. An nginx `client_max_body_size` (or similar) can 413 the
> probe before it reaches PHP, which yields `INCONCLUSIVE`. Do not run it against
> shared hosting you do not control — a crashed worker can affect other tenants.

Setup:

```
python -m venv .venv && .venv/bin/pip install -r requirements.txt
```

## `php2shell-local-audit.sh` — read-only on-box / Docker audit

Run on a host you can log into. **Changes nothing**; reads versions and process
state. Leads at **finding PHP that a network probe cannot see**: builds off
`PATH` (a snap at `/snap/<app>/<rev>/bin/php-fpm`), binaries that won't execute
standalone (version read from the binary's strings, flagged to verify), and PHP
inside running **Docker** containers (reports the image tag too). It also does
the version and restart checks described below.

```
sudo bash php2shell-local-audit.sh
```

## `php2shell-patch-check.sh` — read-only patch & stopgap verifier

Run on a host you can log into. **Changes nothing.** Leads at **deciding
patched vs. not**, especially for distribution packages, and at the two things
the version number alone cannot tell you:

- **Distro backport confirmation.** For a package below the upstream fix
  number, it reads the package **changelog** and confirms the fix only when
  both CVEs are listed — a Debian/RHEL backport keeps the old upstream number
  but patches it, so this avoids both the false "vulnerable" and the false
  "clean". (The audit script flags these "check the package"; this one tries to
  decide.)
- **Restart check.** A worker started before the upgrade keeps the old code
  mapped; `/proc/<pid>/maps` showing a `(deleted)` PHP binary or `libphp` means
  the package is new but the service was not restarted — still vulnerable.
- **Stopgap check (CVE-2026-115560).** Reports `session.upload_progress.enabled`
  in each `php.ini` and FPM pool. PHP advises turning it off until the next
  regular release, for the separate, still-unpatched session-upload-progress
  RCE path disclosed 2026-10-23.
- Covers both **Docker and Podman** containers.

```
sudo bash php2shell-patch-check.sh
# scan extra webroots/app dirs for bundled PHP:
EXTRA_PATHS="/srv/www /opt/app" sudo bash php2shell-patch-check.sh
```

Verdict is `FIXED` only when every runtime found is at/above the fix (or a
changelog-confirmed backport) **and** no running process still maps replaced
PHP files; otherwise it prints each `VULNERABLE` item and why.

### Which on-box script to run

Both do the core version + restart check. Pick by what the host needs, or run
both:

| You want to… | Use |
|---|---|
| Confirm a Debian/RHEL **package** is the backported fix | `php2shell-patch-check.sh` (reads changelog) |
| Check the **`upload_progress` stopgap** for CVE-2026-115560 | `php2shell-patch-check.sh` |
| Find PHP **bundled in a snap / off `PATH`** | `php2shell-local-audit.sh` |
| Check **Podman** containers | `php2shell-patch-check.sh` |
| Check **Docker** containers | either |

## References

- PHP advisories: GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp
- Follow-up: CVE-2026-115560 (session upload progress), informational advisory 2026-10-23
- CISA KEV: CVE-2026-109618, CVE-2026-109619 (added 2026-10-26)
- Vendor/product status: https://github.com/NCSC-NL/php2shell
