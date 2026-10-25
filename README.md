# netconfig

Apply configuration commands to many network devices over SSH, concurrently, from a
single static binary. Built for air-gapped management networks: no runtime
dependencies, no network access other than SSH to the devices.

The same binary also archives configurations and watches them for change and drift:
[`netconfig backup`](#backup-change-detection-and-drift-netconfig-backup) and
`netconfig backup show` (formerly the standalone `netbackup` tool).

Supported platforms: Cisco IOS/IOS-XE, Cisco Small Business (SF/SG/CBS), Cisco ASA, Juniper Junos, Huawei VRP, Fortinet FortiOS, Arista EOS, VyOS, Ruijie RGOS, Aruba AOS-CX/AOS-S, Check Point Gaia, Palo Alto PAN-OS, pfSense, Sophos.

> **Status:** written without access to a Go toolchain or real devices. Nothing here has
> been compiled or run yet. Follow [Verify before first use](#verify-before-first-use)
> and test against lab devices before pointing it at production.


## Quick Start (Universal Deployment)

No matter what device or OS you are using (Linux, macOS, Windows, x86_64, ARM64), you don't need to remember binary names or build steps.

### Option 1: Universal Auto-Detect Script (Linux / macOS / Windows)
Simply execute `./run` (or `.\scripts\run.bat` on native Windows CMD). It automatically detects your host OS and CPU architecture and launches the correct pre-built binary. If no command arguments are passed, it automatically defaults to `-commands commands.txt`:

```bash
make init          # 1. Initialize .env, inventory.csv, and commands.txt
./run              # 2. Automatically launches with -commands commands.txt
./run -dry-run     # 3. Dry-run mode (safe, validates on device)
```

### Option 2: Download from GitHub Releases
All builds are automatically compiled and published to GitHub on every commit:
1. Go to the [Releases](https://github.com/duc-mt/netconfig/releases) page on GitHub.
2. Under **Latest Build**, download the single binary for your target OS (`.exe` for Windows, `linux-amd64` for Linux).
3. Bring only this binary to any machine (online or air-gapped).
4. Run `netconfig.exe -init` (or `./netconfig-linux-amd64 -init`) to generate sample `inventory.csv`, `commands.txt`, and `.env` template files instantly!
5. Run `netconfig.exe` (defaults to `commands.txt`, `inventory.csv`, and `.env` automatically).

### Option 3: Standard Make / Direct Binary
- **Initialize config:** `make init`
- **Build (offline):** `make build` (or `make cross` for all platforms)
- **Run direct binary:** `./bin/netconfig`

## Build

```sh
make vendor     # once, on a machine with internet: go mod tidy && go mod vendor
make build      # CGO_ENABLED=0 go build -mod=vendor -> bin/netconfig
make test       # unit tests (no devices needed)
make cross      # linux/windows/darwin binaries
```

Dependencies are only `golang.org/x/crypto` (`ssh`, `ssh/knownhosts`) and `golang.org/x/term`,
taken from `./vendor`. If you already have a `vendor/` directory, re-run `go mod vendor`
once so it contains the `ssh/knownhosts` package, which this project imports.

## Quick start

### 1. Initialize configuration files

Fastest way (with the single binary, zero dependencies):
```sh
netconfig -init
```
*(Or if using the repository with Make: `make init`)*

This automatically creates `.env` (with `chmod 600`), `inventory.csv`, and `commands.txt` without overwriting existing files.

Or manually:
```sh
cp examples/env.example .env && chmod 600 .env       # credentials
cp examples/inventory.csv inventory.csv              # device inventory
cp examples/commands.txt commands.txt                # commands to push
```

Available example files in `examples/`:

| File | Purpose |
|---|---|
| `env.example` | Credential template; copy to `.env` and `chmod 600` |
| `inventory.csv` | Device inventory template; copy to `inventory.csv` |
| `inventory.example` | Same as above (kept as reference; never overwritten by `make init`) |
| `commands.txt` | Command file template; copy to `commands.txt` |
| `commands.example` | Same as above (reference copy) |
| `config.tmpl` | Go template example for per-device commands |

### 2. Configure credentials and inventory

- Edit `.env` with your SSH credentials (`NETCONFIG_USERNAME`, `NETCONFIG_PASSWORD`).
- Edit `inventory.csv` with target device IPs and vendor platforms.
- Edit `commands.txt` with configuration commands.

### 3. Run

```sh
# First run: test connectivity and record host keys without touching device config
./bin/netconfig -commands commands.txt -dry-run -host-key-policy accept-new

# Production run: push commands with automatic pre-change configuration backup
./bin/netconfig -commands commands.txt -backup

# Operational (show) commands — no configure/commit/save triggered
./bin/netconfig -op -commands <(echo "show ip ospf route | match 248") -yes -host-key-policy accept-new

# Write per-device output files and a JSON run report
./bin/netconfig -op -commands <(echo "show version") -yes \
  -output-dir results/ -json-report run.json -host-key-policy accept-new

# Config change with auto-rollback on failure
./bin/netconfig -commands commands.txt -backup -rollback-on-fail -yes
```

Templates (rendered once per device):

```sh
./bin/netconfig -template examples/config.tmpl -var ntp=10.0.0.1 -var syslog=10.0.0.2 -limit '@dc1' -backup
```

## Features

### Operational Mode (`-op`)

Run read-only commands (e.g. `show`, `display`, `get`) without ever entering
configuration mode. No `configure`, no `commit`, no `save` is issued — the
command runs directly in the device's operational shell.

```sh
./bin/netconfig -op -commands <(echo "show ip ospf route | match 248") \
  -yes -host-key-policy accept-new
```

Output is printed live on the console (at `INFO` level) and always captured in
the audit log. Combine with `-output-dir` to save per-device output files.
`-op` and `-dry-run` are mutually exclusive.

### Per-Device Output Files (`-output-dir DIR`)

Save each device's command responses to `<dir>/<hostname>.txt` for easy
offline review, diffing, or scripting:

```sh
./bin/netconfig -op -commands commands.txt -yes -output-dir results/
ls results/
# NHG-HO-GW-01.txt  NHG-TRANSIT-GW-01.txt  ...
```

Files are written atomically (temp-file + rename) with mode `0600`. The
directory is created automatically. This flag works for both `-op` and normal
configuration runs.

### JSON Run Report (`-json-report FILE`)

Write a machine-readable summary of the entire run to a JSON file — useful for
CI/CD pipelines, dashboards, or post-processing:

```sh
./bin/netconfig -commands commands.txt -backup -json-report run.json
cat run.json
```

The report contains: `generated_at`, `succeeded`/`failed`/`skipped` counts,
and a `devices` array with `hostname`, `address`, `vendor`, `status`,
`category`, `detail`, `duration_ms`, `backup_path`, and `output_file` (if
`-output-dir` was also set).

### Auto-Rollback on Failure (`-rollback-on-fail`)

Requires `-backup`. When a device fails mid-configuration, netconfig
immediately re-opens an SSH session and re-applies the pre-change backup
content as configuration commands, reverting the device to its known-good
state:

```sh
./bin/netconfig -commands commands.txt -backup -rollback-on-fail -yes
```

Rollback is best-effort: the original failure is still recorded in the result
table, and any rollback errors are logged as warnings without masking the root
cause. Use `-verbose` to see full rollback traces.

> **Note:** Platforms without atomic candidate configuration (Cisco IOS,
> Huawei VRP, FortiOS) apply commands immediately to the running config. The
> rollback re-applies the entire backup as individual commands, which may not
> be identical to a native rollback on every platform. Test in a lab before
> relying on this in production.
>
> **Precaution for in-band SSH rollback:** If the pre-change backup modifies
> management interface IPs, AAA credentials, or VTY access-lists, automated
> rollback over in-band SSH could sever the session before completion. For
> disruptive changes, use deadman timers (`-commit-confirm`, `-allow-reboot-rollback`)
> or apply changes with out-of-band console access. See [Precautions When Restoring via CLI Paste](#precautions-when-restoring-via-cli-paste).

### Pre-Flight Safety Lint (`-strict-safety`, `-allow-dangerous`)

Before any SSH session is opened, each device's commands are analysed statically against *that
device's* connection parameters: its management address, SSH port and (when configured in `.env` or
the environment) the login user. A finding has a level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and a
kind that decides which flag releases it:

| Kind | Examples | Blocks the run when | Released by |
|---|---|---|---|
| lockout | removing/re-addressing the management IP, removing the default route (`0.0.0.0/0`), moving or disabling SSH, restricting SSH algorithms, AAA lists without a local fallback, removing the login user, vty ACL/`transport input` changes, shutting an interface, replacing a trunk VLAN list | level is `CRITICAL` | `-force` |
| destructive | `no router bgp`, `delete interfaces`, `default interface`, `clear ip bgp *`, `write erase`, `reload` | level is `HIGH` or `CRITICAL` | `-allow-dangerous` |
| impact | neighbour shutdown/removal, router-id change, VLAN removal, soft resets | never | - |

`-strict-safety` is on by default. When it blocks, netconfig exits with status 1 **before any device is
contacted** and prints every finding. `-strict-safety=false` turns blocks into warnings. `-dry-run` is
never blocked (it prints what would block a real run). Read-only commands (`show`, `display`, `get`,
`ping`, ...) are never flagged, and `-op` runs are checked for destructive commands only.

Lockout detection matches literally: `no ip address 10.0.0.1 ...` is `CRITICAL` only when `10.0.0.1`
is the address netconfig connects to; removing some other address is `HIGH`. A lint failure on one
device (including an internal error) is logged as a warning for that device and never stops the others.

> **Behaviour change:** scripts that already contained destructive commands now need
> `-allow-dangerous` (or `-strict-safety=false`).

### Commit-Confirm (`-commit-confirm`, `-allow-reboot-rollback`)

`-commit-confirm MINUTES` applies the change with an **on-box deadman timer**: if netconfig cannot
verify and confirm in time (lockout, crash, lost link), the device reverts by itself. Each platform
is classified by what it can do:

| Rating (summary table) | `-plan` label | Platforms | Mechanism |
|---|---|---|---|
| `SAFE` | `SAFE` | Junos, VyOS, Arista EOS, Cisco IOS-XE | `commit confirmed N`, `commit-confirm N`, session `commit timer`, `configure terminal revert timer N` |
| `REBOOT REQUIRED` | `REBOOT ONLY` | classic Cisco IOS, Cisco ASA | `reload in N` ... `reload cancel`; needs `-allow-reboot-rollback` |
| `UNSAFE / OOB REQUIRED` | `UNSAFE` | Huawei, FortiOS, Ruijie, Aruba, Cisco Small Business (SF/SG/CBS), Check Point, PAN-OS, pfSense, Sophos | none |

IOS-XE is selected by the vendor names `ios-xe`, `iosxe` or `cisco-ios-xe`; plain `cisco` / `ios` is
treated as classic IOS.

Two further Cisco vendor keys have their own profiles. `cisco_sb` (Cisco Small Business SF/SG/CBS;
aliases `cisco-sf`, `cisco-sg`, `cbs`, `cbs350`, `sg300`, `sg350`, `sg500`, `sf300`, `sf500`) is rated
`UNSAFE`: it has no `reload in`, so `-commit-confirm` never arms a timer on it. `cisco_asa` (aliases
`asa`, `ftd`) is rated `REBOOT ONLY`, like classic IOS. The `ftd` alias only selects this profile:
Firepower Threat Defense's default CLI is not an ASA shell and its configuration is managed centrally,
so changes through it are unverified.

The flow on a `SAFE` device: arm the timed commit, open a **fresh SSH session** and run the platform
probe (an established session survives many lockouts; a new one does not), run the `-verify-file`
checks, and only then confirm. A failed probe or check means the change is **not** confirmed and the
device rolls back on its own (`VERIFY FAILED`). With `-rollback-on-fail`, Junos also reverts at once
(`rollback 1`, `commit`) instead of waiting for the timer. If the timer window runs out before
confirmation, the device is reported `CONFIRM_FAILED` rather than "succeeded". If the arming command
is rejected or looks like an error, the device is **not changed**.

* **Without `-allow-reboot-rollback`** a classic IOS or Cisco ASA device falls back to client-side rollback
  (`-rollback-on-fail`) and a warning says so. With it, `reload in N` is armed before the change and
  cancelled after verification: if anything fails the device *reloads* to its saved configuration.
* **On `UNSAFE` platforms** the run continues without a safety net and logs:
  `Safe commit-confirm cannot be achieved: platform lacks non-reboot auto-rollback. If network isolation occurs, automated rollback will FAIL and OOB/console access will be required.`
* While a timer is armed, backup-based rollback is skipped: the on-box timer owns the revert.
* The window must outlast verification: netconfig refuses `-commit-confirm` values shorter than the
  worst-case retry time of the checks, and always keeps a 15 s margin before confirming.
* The commands are data in `internal/vendor/vendor.go` (`confirmApply`). IOS-XE and VyOS syntax and
  behaviour vary by release (some VyOS releases implement `commit-confirm` with a reboot): if yours
  differs, adjust the template or the `safety` class there.

### Post-Change Verification (`-verify-file`)

`-verify-file FILE` runs read-only health checks on every device right after its change is applied
(see `examples/verify.example`):

```
verify show ip bgp summary
  expect: Established          # also: contains / not-contains / regex
  not-contains: Idle
  retries: 6                   # optional: give the network time to converge
  interval: 10s
  vendors: cisco, arista       # optional filters
  hosts: edge-*
```

The same blocks can be embedded in a commands file or template as `!@verify ...` / `!@  expect: ...`
comment lines. A rule with no condition, an invalid regex, or a state-changing verb (`configure`,
`reload`, `no`, `commit`, ...) is a startup error. Failed checks are logged as errors, the device
is marked `VERIFY FAILED` (`VERIFY_FAILED` in the reports, which also carry `verify_passed` /
`verify_total`), and with `-rollback-on-fail` the rollback engine runs immediately. One failing
device never affects the others. Checks do not run in `-dry-run` or `-op`.

### Impact Preview (`-plan`)

`-plan` runs the static lint, renders an impact matrix and asks before proceeding (it replaces the
classic prompt; `-yes`/`-force` skip the question, and `-plan -dry-run` previews a dry run):

```
╭──────┬────────┬──────┬──────────┬─────────────────────┬─────────────╮
│ HOST │ VENDOR │ CMDS │ RISK     │ IMPACT              │ ROLLBACK    │
├──────┼────────┼──────┼──────────┼─────────────────────┼─────────────┤
│ sw1  │ ios    │    3 │ CRITICAL │ Routing / Interface │ REBOOT ONLY │
│ r1   │ junos  │    1 │ LOW      │ System              │ SAFE        │
╰──────┴────────┴──────┴──────────┴─────────────────────┴─────────────╯
Proceed with applying changes to 2 device(s)? [y/N]:
```

The findings behind each risk level are listed under the table, and with `-commit-confirm` every
device that is not `SAFE` gets a rollback hazard line.

### Canary & Phased Batch Rollouts (`-canary`, `-batch-size`, `-max-fail-percent`)

Safely roll out configuration updates in staged waves with failure thresholds:

```sh
# Run 1 canary device first; if successful, process remaining devices in batches of 5.
# Abort immediately if cumulative failures exceed 10%.
./bin/netconfig -commands commands.txt -canary 1 -batch-size 5 -max-fail-percent 10 -backup
```

- **`-canary N`**: executes `N` devices first as a canary wave. If any canary device fails, the entire run halts immediately; all unstarted devices are marked `SKIPPED (CANARY_FAILED)`.
- **`-batch-size N`**: executes remaining devices in sequential batches of `N` devices (concurrency within each batch is governed by `-concurrency`).
- **`-max-fail-percent P`**: specifies a cumulative failure rate threshold (0–100%). If the failure percentage exceeds `P%` after any batch, remaining batches are aborted and remaining devices are marked `SKIPPED (THRESHOLD_EXCEEDED)`.

### Pre-Commit Candidate Diffing & Interactive Confirmation (`-pre-diff`, `-confirm-diff`)

Inspect exact device-side candidate configuration diffs before committing changes:

```sh
# Inspect candidate diff (Junos "show | compare", VyOS "compare", Arista "show session-config diffs")
./bin/netconfig -commands commands.txt -pre-diff

# Require interactive confirmation before each device's commit
./bin/netconfig -commands commands.txt -confirm-diff
```

- **`-pre-diff`**: stages configuration commands and issues the vendor's native candidate diff command before persisting. The diff is displayed with colored unified diff formatting (`+` additions in green, `-` deletions in red) and stored in `run.json` (`candidate_diff`).
- **`-confirm-diff`**: displays the candidate diff and prompts the operator `[y/N]` to confirm committing each device. If rejected, the candidate changes are discarded cleanly without saving (`rollback 0` on Junos, `abort` on Arista, `exit discard` on VyOS), and the device is safely aborted (`CANCELLED`). Can be bypassed in CI/CD with `-yes` or `-force`.

### Structured Output Parsing (`-op -format json`)

Extract structured data from operational `show`, `display`, and `get` commands directly into JSON:

```sh
# Parse operational commands into structured JSON on stdout
./bin/netconfig -op -commands <(echo "show ip interface brief") -format json -yes
```

The structured output parser automatically recognizes and converts command outputs into typed JSON models:
- **Interface Brief:** `show ip interface brief` (Cisco, Arista), `display ip interface brief` (Huawei), `show interfaces terse` (Junos), `show interfaces` (VyOS).
- **System Version:** `show version` (Cisco, Arista, Junos, VyOS), `display version` (Huawei), `get system status` (FortiOS) — extracts `version`, `model`, `uptime`, `serial_number`, `system_image`.
- **Routing Tables:** `show ip route` (Cisco, Arista, VyOS), `display ip routing-table` (Huawei).
- **Generic Tables & Key-Values:** Any ASCII table or `Key: Value` output is parsed into JSON arrays and maps.

When used with `-output-dir DIR`, parsed results are written to `<DIR>/<hostname>.json`. When used with `-json-report FILE`, each device entry includes `parsed_output`.

### Live Terminal Progress Dashboard (`-dashboard`)

When running interactively on a terminal, `netconfig` renders a live, multi-line ANSI terminal progress dashboard with zero external dependencies:

```
netconfig [Batch 1/3] [Workers: 5] [Active: 3] [Elapsed: 00:12]
[=========>-------------------] 12/30 (40%) | 11 OK, 1 FAIL, 0 SKIP
  * core-rtr-01      (cisco)   [config]    interface GigabitEthernet0/1 (1.2s)
  * dist-sw-02       (junos)   [persist]   commit (2.4s)
  * border-gw-01     (vyos)    [inspect]   compare (0.8s)
```

- **`-dashboard`**: enabled by default on interactive terminals when not in `-verbose` mode.
- Shows real-time progress bars, completed/failed/skipped device counters, elapsed time, current batch/canary status, and active worker operations.
- Interleaves cleanly with log messages and clears itself upon completion, leaving only the clean final summary table.
- Disable via `-dashboard=false` or set `NO_COLOR=1` / run non-interactively in CI pipelines.

## Backup, change detection and drift (`netconfig backup`)

```sh
./run backup                                    # every device in inventory.csv
./run backup -limit '@dc1' -concurrency 20      # one credential group, 20 at a time
./run backup -dry-run                           # prove login and paging setup; save nothing
./run backup -golden-dir golden -html-report 'backups/{run}/report.html' -md-changelog reports/CHANGELOG.md
./run backup show core-sw1                      # view the newest backup of a device
./run backup -h                                 # every flag
```

`backup` reads the same `inventory.csv`, credentials (`.env`, `NETCONFIG_*`), jump hosts, host-key
policy and route memory as a configuration run, and connects through the same engine, so login,
`enable`, paging and per-vendor quirks behave identically. For each device it runs the platform's
backup command, validates that the output is complete, masks secrets, compares it with the previous
backup, saves it, prunes old backups, and reports. One device failing never stops the others.
`-limit` takes comma-separated hostname globs or `@group`, exactly as in a configuration run.

> `backup` is not the classic runner's `-backup` flag. That takes a pre-change snapshot of the
> devices it is about to change, as flat `backups/<host>_<timestamp>.cfg` files. The two can share
> the `backups/` directory without interfering; `backup` and `backup show` only read and write
> the `backup-*` run directories described below.

### Where backups go

```text
backups/
  backup-2026-10-12-0757/              one directory per run
    cisco_ios/core-sw1.cfg             <platform>/<hostname><extension>
    cisco_ios/core-sw1.diff            only when the configuration changed since last time
    juniper_junos/edge-mx1.set
```

| Platform (vendor key) | Directory | Extension |
|---|---|---|
| `cisco`, `cisco_sb`, `cisco_asa`, `huawei`, `arista`, `aruba`, `ruijie`, `paloalto` | `cisco_ios`, `cisco_sb`, `cisco_asa`, `huawei_vrp`, `arista`, `aruba`, `ruijie`, `paloalto` | `.cfg` |
| `sophos` | `sophos` | `.cfg` (CLI network interface/zone dump for drift auditing; see note below) |
| `junos` | `juniper_junos` | `.set` (archived as `show configuration \| display set`, one statement per line) |
| `fortinet` | `fortigate` | `.conf` |
| `checkpoint` | `checkpoint_gaia` | `.cfg` |
| `pfsense` | `pfsense` | `.xml` |
| `vyos` | `vyos` | `.config` |
| `mikrotik` | `mikrotik` | `.rsc` |

> [!NOTE]
> **Sophos SFOS Architecture & Multi-Command Backup**:
> Unlike Cisco, FortiOS, or Junos, Sophos SFOS does not store configuration in flat text files. Settings reside in an internal PostgreSQL database (`corporate.db`). The SFOS Device Console (`console>`) does not provide a CLI command to dump a full importable configuration (like `running-config`).
> Therefore, `netconfig` executes a comprehensive suite of show commands under `sophos/<hostname>.cfg` for configuration drift tracking, change detection (`.diff`), and network state documentation:
> 1. `system diagnostics show version-info` (Firmware version, build, serial number, device ID)
> 2. `show network interfaces` (Physical & virtual interfaces, zones, IP/netmask, MTU, speed/duplex)
> 3. `show static-route` (Active static routing table)
> 4. `system ha show details` (High Availability cluster mode, node status, peer health)
> 
> Each command output is clearly demarcated with `=== <command> ===` section banners.
> To obtain a native 1-click importable backup, use WebAdmin (*Backup & Firmware > Backup & Restore* for `.backup` binary archives, or *Import Export* for `Entities.xml` packages) or the Sophos Central / XML API over HTTPS.

The directory names are the ones the standalone netbackup used, so an existing backup tree, its
retention and its "diff against the previous backup" carry straight over. Backups and diffs are
written `0600` in `0700` directories, atomically (a crash never leaves a half-written file).

A backup is only saved if it passes the platform's validation: no error from the device, and the
platform's end-of-configuration marker present (`: end` on an ASA; `exit` or `end` as the **last**
line on Small Business, whose `exit` also closes every block). A truncated capture is reported as
`TRUNCATED_OUTPUT` and never replaces a good backup.

### Change detection and retention

* A device whose configuration is unchanged since the last run is reported `UNCHANGED` and nothing is
  written (`-force` saves it anyway). Otherwise the new file is saved and the `.diff` shows `+`/`-`.
* **Volatile lines are ignored** when comparing (`-ignore-volatile`, default on): `! Last configuration
  change at ...`, `Current configuration : N bytes`, Junos `## Last changed`, ASA `: Written by ...`,
  VyOS/pfSense/Gaia generated-on banners, uptime and `ntp clock-period` counters. A device whose only
  differences are such lines is `UNCHANGED (volatile lines only)`. The saved file is never filtered.
  Add site-specific noise with `-volatile-patterns <file>` (see `examples/volatile-patterns.txt`).
* **Large configurations are fine.** The diff costs time and memory in proportion to the number of lines
  that *changed*, not the size of the file: a 100,000-line configuration with a few edits diffs in
  milliseconds. It is skipped (with a warning, and the new backup is still saved) only when more than 3,000
  lines changed, i.e. the configuration was replaced wholesale, or the two files exceed 400,000 lines together.
* **Retention** keeps the newest `-retention-count` backups per device (default **10**; 0 disables) and,
  with `-retention-days N`, deletes those older than N days. Only `backup-*` run directories are touched.

### Secrets are masked on disk

With `-redact` (default on) passwords, password and enable hashes, pre-shared keys, SNMP communities,
RADIUS/TACACS keys and similar are replaced by `<REDACTED>` before anything is written. It understands
the multi-token forms of each platform (`enable password level 15 encrypted <hash>`, `username x
password encrypted <hash>`, ASA `ikev1 pre-shared-key` / `failover key` / `snmp-server host ... community`).

* **Limitation:** because secrets are stored masked, *rotating* a password produces no diff. Creating,
  deleting or re-parameterising a user or community is still detected.
* Masking is pattern based. It is a safety net, not a vault: keep the backup directory access-controlled,
  and use `-redact=false` only where you need restorable configurations and trust the storage.

### Risk classification

Every added or removed diff line is classified; the highest level found is attached to the device.

| Level | Triggers |
|---|---|
| **CRITICAL** | AAA / TACACS / RADIUS, local users and credentials, SNMP communities, ACLs, firewall rules, SSH port / ciphers |
| **WARNING** | BGP, OSPF, default and static routes, VLANs, interface `shutdown` / `no shutdown` |
| **INFO** | NTP, description / remark, hostname, banner |

It shows next to the diff counts in the result table, in the run summary (`RISK=CRITICAL(ACL)`), as an
inline `<== CRITICAL: ACL` marker on the offending diff lines (logged at `WARN`), and in a **Risk alerts**
block at the end of the run. Description and remark lines never escalate. Rules live in
`internal/backup/risk.go` (`builtinRiskSpecs`, first match wins).

### Golden-config compliance

`-golden-dir <dir>` holds one `<vendor>.golden` per platform (the vendor key or any alias: `cisco.golden`,
`cisco_ios.golden`, `asa.golden`, `sg350.golden`, `h3c.golden`, ...) plus an optional `common.golden` for
every device; `-compliance-rules <file>` takes `[vendor]` sections instead. See `examples/golden/`.
Cisco SB and Cisco ASA do **not** inherit the IOS rules, since their CLI differs. A baseline for a
platform netconfig does not support (MikroTik) is reported as an error, not silently ignored.

```text
# A comment ("!" and "//" also start one), on its own line.
service password-encryption          # required line (exact match)
re: ^ntp server\s+\S+                # at least one line must match this regex
not: ip http server                  # forbidden line
not-re: community\s+public\b         # no line may match this regex
```

Drifts are reported per device as `missing`, `mismatch` or `forbidden`; devices are checked on every run,
including unchanged ones. A baseline that cannot be loaded only disables the check (a warning); it never
stops the backup.

### Reports and the result table

* `-result-table` (default on) prints a per-device table (status, risk, compliance, size, duration, error)
  to stdout after the run. Progress, the run summary and the risk alerts go to stderr and the log file.
* `-html-report` writes one self-contained HTML file (no scripts, no external resources); `-md-changelog`
  keeps a running Markdown changelog (newest run first; a file not created by this tool is appended to,
  never overwritten); `-json-report` and `-csv-report` are for CMDB ingestion. Paths may contain `{run}`,
  `{timestamp}` and `{date}`. A report that cannot be written is a warning and never changes the exit code.
* Exit status: `0` every device succeeded, `1` usage or configuration error, `2` the run finished but at
  least one device failed.

### Failures and retries

Failures are classified: `CONNECTION_TIMEOUT_OR_UNREACHABLE`, `CONNECT_FAILED`, `AUTHENTICATION_FAILED`,
`COMMAND_REJECTED_OR_FAILED`, `COMMAND_TIMEOUT`, `SSH_SESSION_ERROR`, `TRUNCATED_OUTPUT`, `LOCAL_IO_ERROR`,
`UNKNOWN_ERROR`. With `-retries N` a
device is retried after connection problems, timeouts, dropped sessions and truncated output, but
**never** after a rejected password (every attempt counts towards an account lockout), a changed host key,
or a command the device refused. A device whose credentials are missing is not contacted at all.

### Key flags

| Flag | Default | |
|---|---|---|
| `-inventory` | `inventory.csv` | device list |
| `-limit` | all | hostname globs (comma-separated) or `@group` |
| `-backup-dir` (`-out`) | `backups` | where run directories are created |
| `-retention-count` / `-retention-days` | `10` / `0` | how many / how old to keep (0 = no limit) |
| `-redact` | on | mask secrets in saved files |
| `-force` (`-save-unchanged`) | off | save even if unchanged |
| `-ignore-volatile`, `-volatile-patterns` | on, none | semantic diff |
| `-golden-dir`, `-compliance-rules` | none | drift checking |
| `-html-report`, `-md-changelog` (`-md-report`), `-json-report`, `-csv-report` | none | reports |
| `-concurrency` | `10` | devices in parallel (one session per address at a time) |
| `-retries`, `-retry-delay`, `-dial-jitter` | `0`, `2s`, `100ms` | resilience |
| `-connect-timeout`, `-command-timeout` | `10s`, `30s` | the backup command itself gets 3x |
| `-dry-run` | off | connect, log in and set up paging; no command, no files |
| `-host-key-policy` (`-known-hosts-policy`), `-known-hosts`, `-legacy-algorithms` | `update`, `~/.ssh/known_hosts`, on | as for a configuration run |
| `-jump`, `-jump-host`, `-mesh-fallback`, `-memory` | on, none, off, on | routing; `-mesh-fallback` is opt-in |

### Viewing backups: `backup show`

`show` is a subcommand of `backup`, in the same way `user add` is a subcommand of `user`:
`./run backup` takes a backup, `./run backup show` looks at one.

```sh
./run backup show core-sw1        # newest backup, in $PAGER (or less) on a terminal, printed otherwise
./run backup show gw-01           # a part of a name works (case-insensitive); you choose if several match
./run backup show -d core-sw1     # the newest diff
./run backup show -p core-sw1     # just the file's path (for scripts: cat "$(./run backup show -p core-sw1)")
./run backup show -l              # every device that has a backup
./run backup show -h              # its flags
```

It honours `-backup-dir` and works for every platform's extension. When several devices match and there
is no terminal to ask on, it lists them and exits `1`. Only the *first* argument after `backup` selects
`show`, so a flag value such as `-limit show` is still a device filter.

### Restoring from Backup & Disaster Recovery

When recovering devices using saved backups under `<backup-dir>/<run>/<vendor_dir>/<hostname><ext>`, operators can choose between **native file-based restoration** (recommended for full disaster recovery) and **interactive CLI pasting** (for targeted section rollbacks).

#### Platform-by-Platform Recovery Procedures

| Platform | Format & Path | Native / File-Based Recovery (Recommended) | CLI Paste Procedure |
| :--- | :--- | :--- | :--- |
| **Check Point Gaia** | `checkpoint_gaia/*.cfg` | `clish -s -f <file.cfg>` or `load configuration <file.cfg>`<br>*(WebUI: Device > System Operations > Restore)* | Ensure `set clienv on-failure continue` is at line 1, then paste line-by-line into Clish |
| **Fortinet FortiOS** | `fortigate/*.conf` | `execute restore config tftp/ftp/usb <file.conf>`<br>*(WebUI: System > Configuration > Restore)* — reboots clean | Paste blocks directly (configure terminal pacing to avoid dropping keys) |
| **Cisco IOS / IOS-XE** | `cisco_ios/*.cfg` | Atomic (Zero-Reboot): `configure replace tftp://<srv>/<host>.cfg force`<br>Cold: `copy tftp:... startup-config && reload` | Enter `configure terminal`, paste with 20–50ms delay, `end`, `write memory` |
| **Cisco Small Business** | `cisco_sb/*.cfg` | `copy tftp://<srv>/<host>.cfg startup-config && reload`<br>*(WebUI: Administration > File Management > File Operations)* | Enter `configure terminal`, paste with 30ms pacing delay, `end`, `write memory` |
| **Cisco ASA** | `cisco_asa/*.cfg` | `copy tftp://<srv>/<host>.cfg startup-config && reload` | Paste under `configure terminal`, then `write memory` |
| **Juniper Junos** | `juniper_junos/*.set` | In `configure`: `load set /var/tmp/<host>.set`, verify with `commit check`, then `commit`<br>*(Disaster recovery: `load factory-default` -> `load set ...` -> `commit`)* | Enter `configure`, paste `set ...` commands, verify with `commit check`, `commit` |
| **Huawei VRP** | `huawei_vrp/*.cfg` | Transfer to flash, then: `startup saved-configuration <host>.cfg && reboot fast` | Enter `system-view`, paste commands with pacing delay, `return`, `save` |
| **Arista EOS** | `arista/*.cfg` | Atomic: `configure replace <file.cfg>` (zero-reboot running config replace)<br>Cold: `copy <file.cfg> startup-config && reload` | Enter `configure`, paste commands, `commit`, `write memory` |
| **Aruba AOS-CX / AOS-S** | `aruba/*.cfg` | AOS-CX: `copy <file.cfg> checkpoint <name>` then `checkpoint rollback <name>`<br>Cold: `copy <file.cfg> startup-config && boot system` | Enter `configure terminal`, paste commands, `write memory` |
| **VyOS** | `vyos/*.config` | In configure mode: `load /config/<host>.config`, verify with `compare`, then `commit && save` | Paste `set ...` lines in configure mode, `commit`, `save` |
| **MikroTik RouterOS** | `mikrotik/*.rsc` | `/import verbose=yes file-name=<host>.rsc`<br>*(Cold reset: `/system reset-configuration run-after-reset=<host>.rsc keep-users=no`)* | Paste script directly into terminal |
| **Palo Alto PAN-OS** | `paloalto/*.cfg` | CLI: `scp import configuration from ...` then in configure: `load config from <file.cfg>` and `commit`<br>*(WebUI: Device > Setup > Operations > Import snapshot)* | Paste `set ...` lines under `configure`, `commit` |
| **pfSense** | `pfsense/*.xml` | WebUI: *Diagnostics > Backup & Restore > Restore configuration*<br>*(CLI: Place at `/conf/config.xml` and run `/etc/rc.reload_all`)* | N/A (XML format: restore via WebUI or filesystem) |
| **Ruijie RGOS** | `ruijie/*.cfg` | `copy tftp://<srv>/<host>.cfg startup-config && reload` | Enter `configure terminal`, paste with 30ms pacing delay, `end`, `write` |
| **Sophos** | `sophos/*.cfg` | **Audit/Documentation Only**: `sophos/*.cfg` captures the CLI network interface and zone state (`show network interfaces`) for drift auditing. For full system recovery, use native SFOS backups: WebUI (*Backup & Firmware > Backup & Restore*) or Advanced Shell (`/bin/opcode system_backup_now -ds nosync` in `/var/conf/backupdata/`) | N/A (database-driven: restore native `.backup` or `Entities.xml` package via WebUI) |

#### Precautions When Restoring via CLI Paste

If pasting full configuration backups into a live switch (e.g., using SecureCRT, PuTTY, iTerm2, or serial console):

1. **Line Pacing / Buffer Overflow:**
   * Avoid dumping thousands of bytes into a terminal emulator at once.
   * Set a **20–50 ms inter-line paste delay** in your terminal client (e.g., SecureCRT: *Session Options > Terminal > Emulation > Advanced > Paste Delay*; iTerm2: *Preferences > Advanced > Paste delay*; PuTTY paste delays).
   * Device UART and PTY input buffers (notably on Cisco Catalyst/IOS, Ruijie RGOS, and Comware switches) easily overflow during rapid multi-line pastes, causing dropped characters, corrupted crypto keys/secrets, truncated ACL remarks, or syntax errors.

2. **Session Interruption & Command Ordering:**
   * Ensure commands affecting management connectivity (such as `ip access-list standard VTY-ACL`, `access-class` under `line vty`, management VLAN interface IPs, default gateways, or AAA/SSH authentication) are applied **last**, immediately before `end` and `write memory` (or `commit`).
   * If pasted over an in-band SSH session, modifying management parameters mid-paste instantly drops the connection before reaching the save step, leaving the device half-configured and unmanageable remotely.

3. **Prefer Out-of-Band (OOB) / Console Access:**
   * For bare-metal disaster recovery or whole-configuration restores, connect via direct serial console or dedicated out-of-band management network whenever possible to eliminate the risk of mid-paste session drops.

### Migrating from the standalone `netbackup`

`netbackup <flags>` becomes `netconfig backup <flags>`, and browsing backups uses
`netconfig backup show` / `./run backup show` (there is no `netconfig show-backup` command). Existing
inventories, `.env` files, golden baselines and backup trees keep working:

* **Flags**: netbackup's spellings stay accepted: `-out`, `-md-report`, `-save-unchanged`,
  `-known-hosts-policy`, `-update-known-hosts`, `-replace-host-keys`, `-insecure-ignore-host-key`,
  `-show-diff`.
* **Environment**: `NETBACKUP_<X>` is read as `NETCONFIG_<X>` (an explicit `NETCONFIG_` name wins), with a
  warning to rename it.
* **Vendor names**: every vendor spelling netbackup accepted (`cisco_ios`, `juniper_junos`, `fortigate`,
  `checkpoint_gaia`, `huawei_vrp`, ...) still resolves; backups keep landing in the same directories.

What differs, deliberately:

* `-retention-count` defaults to **10** (netbackup: 0, keep everything).
* `-mesh-fallback` is **opt-in**; netbackup always tunnelled through neighbouring devices when a direct
  connection failed, which routes credentials through other devices.
* `-verbose` logs the connection and login steps (as in a configuration run); in netbackup it aliased `-diff`.
* `-log-format json` is rejected with a pointer to `-json-report`. `-init`, `-show-memory` and
  `-clear-memory` stay on the top-level command (`netconfig -init`).
* Authentication failures, host-key mismatches and refused commands are **no longer retried** by `-retries`.
* **MikroTik RouterOS and the `generic` platform are not supported** (netconfig has no profile for them);
  such devices fail with `unsupported vendor` and a `mikrotik.golden` file is reported as an error.
* If a commands file is literally named `backup`, pass it as `-commands backup`.

## Inventory

```csv
hostname,address,port,vendor,credential_group
core-sw1,10.10.0.11,22,cisco,dc1
edge-mx1,10.20.0.1,,junos,dc2
```

Header, blank lines and `#` comments are optional. Empty `port` means 22, empty
`credential_group` means `default`. Vendor accepts aliases (`ios`, `ios-xe`, `eos`, `juniper`,
`vrp`, `fortios`, `fortigate`, `cisco_sb`, `sg350`, `cisco_asa`, `asa`, `h3c`, ...). All row errors are reported together with line numbers.
`-limit 'core-*,@dc2'` selects by hostname glob or `@credential_group`; a pattern that
matches nothing is an error.

## Commands and templates

`-commands FILE`: one command per line; blank lines and lines starting with `#` or `!` are skipped.
`-template FILE`: Go `text/template`, rendered per device. Available: `.Hostname .Address .Port
.Vendor .Group` (`.Vendor` is the canonical name) and `.Vars.<name>` from `-var name=value`.
Functions `upper` and `lower`. An undefined variable is an error, not `<no value>`.
A device whose template renders nothing is reported as `SKIPPED (NO_COMMANDS)`.

Exactly one of `-commands` / `-template` is required. Everything is rendered and validated
before any device is contacted.

Limitation: commands that open a multi-line input (for example IOS `banner motd ^C ... ^C`)
do not return a prompt line by line and will time out. Use a vendor-specific method for those.

## Credentials

Per field (username, password, enable password), highest priority first:

1. `.env` file (`-env-file`, default `./.env`; never exported into the process environment)
2. process environment variables
3. interactive prompt on the terminal (username echoed, password not)

Names: `NETCONFIG_USERNAME`, `NETCONFIG_PASSWORD`, `NETCONFIG_ENABLE_PASSWORD`, and per
credential group `NETCONFIG_<GROUP>_USERNAME` etc. (`dc-1` becomes `DC_1`). A group-specific
variable overrides the global one, whichever source it comes from, so a per-site override
in the environment beats a global default in `.env`. Empty values count as unset. Each group is
prompted for at most once. If nothing resolves (and there is no terminal), the group's devices are
`SKIPPED (NO_CREDENTIALS)` and the others still run.

Passwords are never accepted as flags (they would show up in `ps`). The logger masks every
resolved password wherever it would appear, and well-known secret-bearing config lines
(`... password 0 X`, `enable secret 5 X`, `snmp-server community X`, `set psksecret X`, ...) are
masked in logs and in the confirmation preview; what is *sent* to the device is never altered.
`.env` readable by group/others triggers a warning.

## Safety model

* **Confirmation:** before changing live devices netconfig prints the targets and commands and
  asks `[y/N]`. `-yes` / `-force` skips it. Without a terminal and without `-yes` it refuses to
  run. `-dry-run` needs no confirmation. `-plan` shows the impact matrix first (see below).
* **Pre-flight lint, commit-confirm, verification:** see the three sections above. They are
  independent: lint runs before any connection, the deadman timer and checks protect the change
  itself, and `-backup` / `-rollback-on-fail` remain the fallback for platforms without a timer.
* **Backup (`-backup`, `-backup-dir backups`):** each device's running configuration is saved
  (mode 0600, written atomically) *before* anything is changed. If the backup fails, that device is
  not touched (`BACKUP_FAILED`). When restoring backups manually via CLI paste, follow the
  [restoration precautions](#precautions-when-restoring-via-cli-paste) (pacing delay and command ordering).
* **Stop on first error per device:** a rejected command ends that device's run. Cleanup leaves
  configuration mode **without saving** (Cisco/Arista `end` and no `write memory`; Junos `rollback 0`
  and no commit; Huawei `return`, no `save`; FortiOS `abort`). Other devices are unaffected.
  Note that IOS, VRP and FortiOS apply commands immediately, so earlier commands of a failed run
  stay in the running config until reload/rollback; that is what `-backup` is for.
* **Dry run (`-dry-run`):**

  | Platform | What dry-run does |
  |---|---|
  | Junos | `configure`, your commands, `show \| compare`, `commit check`, `rollback 0`, `exit`: real device-side validation, nothing committed |
  | Arista EOS | config session: your commands, `show session-config diffs`, `abort`: validated, nothing applied |
  | Cisco (IOS, SB, ASA), Huawei, FortiOS | no candidate configuration exists, so only connectivity/login/privilege and a read-only probe (`show clock`, `display clock`, `get system status`); the commands that *would* run are listed in the log but not sent |

  Dry run never sends `commit`, `write memory` or `save`.
* **Interrupt (Ctrl-C):** no new devices start, running ones get the safe cleanup above, the
  summary is still printed. A second Ctrl-C force-quits.
* **Auto-confirm (`-auto-confirm`, default on):** dialogs such as `[y/n]`, `[confirm]`, `(y/n)`,
  `[yes,no]` and Huawei's file-name prompt are answered, and every answer is written to the log.
  If your commands include something destructive (`reload`, `erase`), remember it will be confirmed;
  use `-auto-confirm=false` to make such prompts fail instead.

## Vendor behaviour

| Platform | Enter | Leave / persist | Notes |
|---|---|---|---|
| Cisco IOS/IOS-XE | `configure terminal` | `end`, `write memory` | `enable` is issued if the login lands in user EXEC; `terminal length 0` |
| Cisco Small Business (SF/SG/CBS) | `configure terminal` | `end`, `write memory` | `terminal datadump`, then `terminal length 0` (a device rejects the one its firmware lacks); the `More: <space>` pager and the save prompt `Overwrite file [startup-config].... (Y/N)[N] ?` (answered `Y`) are handled; a backup must *end* with `exit` or `end` (checked on the last line, because `exit` also closes every block) or it is rejected as truncated, which matters because the backup is this platform's only rollback source |
| Cisco ASA | `configure terminal` | `end`, `write memory` | `terminal pager 0`; a backup ends in `: end`; rejections are printed as `ERROR: ...`; the `Save? [Y]es/[N]o:` question that can precede `reload in` is answered `y` |
| Junos | `configure` | `commit`, `exit` | `set cli screen-length 0` |
| Huawei VRP | `system-view` | `return`, `save` | `screen-length 0 temporary`; `h3c`, `comware` and `hp-comware` are aliases |
| FortiOS | none (commands are `config ... end` blocks) | saved by each `end` | `--More--` is answered, nothing is changed on the device |
| Arista EOS | `configure terminal` | `end`, `write memory` | `terminal length 0` |

Commit/save/backup steps get 3x `-command-timeout`.

## Host keys and connection resilience

Default `-host-key-policy update`: hosts are verified against standard OpenSSH `known_hosts` files without generating a redundant local `./known_hosts`. Unknown hosts and replaced/rotated host keys are automatically updated and learned in `known_hosts`.
- **Automatic 3-OS Discovery**:
  - **Linux / macOS**: Reads `~/.ssh/known_hosts` (and `/etc/ssh/ssh_known_hosts` / `/etc/ssh/ssh_known_hosts2` if present).
  - **Windows**: Reads `%USERPROFILE%\.ssh\known_hosts` (and `%ProgramData%\ssh\ssh_known_hosts` if present).
  - Supports tilde (`~`) expansion in `-known-hosts` if custom paths are provided.
- **Auto-Replace Changed Host Keys (`-host-key-policy update` / `-update-known-hosts` / `-replace-host-keys`)**:
  Default behavior. Automatically removes mismatched/stale existing keys and learns the new device key in `known_hosts` atomically, eliminating the need to manually run `ssh-keygen -R <host>`.
- **First contact enrollment**: Run with `-host-key-policy accept-new` to enroll devices on first contact only (trust-on-first-use; securely appends only to the user's `~/.ssh/known_hosts` / `%USERPROFILE%\.ssh\known_hosts`, preventing duplicates; a *changed* key is rejected).
- **Strict enforcement**: Run with `-host-key-policy strict` to reject unknown hosts and changed host keys with `HOSTKEY_FAILED`.
- `insecure` disables verification and logs a warning.
- **Algorithm Negotiation & Legacy Fallback**: Modern algorithms (including `diffie-hellman-group16-sha512` and `diffie-hellman-group-exchange-sha256`) are preferred. `-legacy-algorithms` is enabled by default (`true`), offering seamless negotiation for older devices requiring `3des-cbc`, `diffie-hellman-group1-sha1`, `diffie-hellman-group-exchange-sha1`, `arcfour`, or `ssh-dss`. Automatic detection retries with legacy algorithms if a cipher/kex mismatch occurs.
- **Per-IP Concurrency Serialization**: Workers serialize connections targeting the same device IP address, preventing concurrent tasks from saturating switch limits (such as JunOS `connection-limit 10`).
- **Transient Rate-Limit Auto-Backoff**: Handshake drops caused by token-bucket rate limits (e.g. JunOS `rate-limit 5`) automatically pause 3.0s–4.5s for replenishment and retry transparently.

## Logging and results

Console (stderr, coloured on a terminal, `-no-color` / `NO_COLOR` to disable) and a timestamped file
`logs/netconfig-YYYYMMDD-HHMMSS.log` (mode 0600). The file always contains the exact command traces
(`>>`) and device responses (`<<`) per device, tagged `[hostname]`; the console shows them with
`-verbose`. Backup contents are written to the backup files, not to the log.

End-of-run table features modern rounded borders (`╭ ╮ ╰ ╯`), colored status badges, and right-aligned metrics:

```text
netconfig run summary (DRY-RUN: nothing was committed or saved)
╭────────────────────┬──────────────────┬────────┬─────────────┬─────────┬────────┬──────┬─────────────────────────────────────────────────────────╮
│ HOST               │ ADDRESS          │ VENDOR │ STATUS      │ APPLIED │ REASON │ TIME │ DETAIL                                                  │
├────────────────────┼──────────────────┼────────┼─────────────┼─────────┼────────┼──────┼─────────────────────────────────────────────────────────┤
│ NHG-TRANSIT-GW-01  │ 10.255.255.4:22  │ vyos   │ ✔ SUCCEEDED │     1/1 │ -      │ 2.8s │ dry-run: 1 command(s) validated on device, nothing kept │
│ NHG-HO-GW-01       │ 10.255.255.6:22  │ vyos   │ ✔ SUCCEEDED │     1/1 │ -      │ 2.9s │ dry-run: 1 command(s) validated on device, nothing kept │
╰────────────────────┴──────────────────┴────────┴─────────────┴─────────┴────────┴──────┴─────────────────────────────────────────────────────────╯

  ✔ Succeeded: 2  │  ✖ Failed: 0  │  ⊘ Skipped: 0  │  (total 2)
```

Columns: host, address, vendor, status, applied commands, reason, time, detail, followed by counts and the hosts per failure reason.


| Reason | Meaning |
|---|---|
| `AUTH_FAILED` | login or enable credentials rejected |
| `CONNECT_FAILED` | unreachable, refused, handshake error |
| `HOSTKEY_FAILED` | host key unknown or changed |
| `TIMEOUT` | connect, prompt or command exceeded its budget (`-connect-timeout`, `-command-timeout`) |
| `SYNTAX_ERROR` | device rejected a configuration command |
| `MODE_ERROR` | could not enter/leave configuration mode |
| `COMMIT_FAILED` | commit, save or `commit check` failed |
| `BACKUP_FAILED` | pre-change snapshot failed; nothing changed |
| `SESSION_ERROR` | connection dropped / unexpected CLI behaviour |
| `PANIC` | internal error, isolated to that device |
| `CANCELLED` | interrupted |
| `UNSUPPORTED_VENDOR`, `NO_CREDENTIALS`, `NO_COMMANDS` | skipped, never contacted |

Exit codes: **0** every selected device succeeded, **1** fatal configuration/usage error (also:
declined at the prompt, refused to run unattended), **2** at least one device failed or was skipped.

## Flags

`netconfig -h` prints all of them. Defaults: `-inventory inventory.csv`, `-concurrency 5`,
`-connect-timeout 10s`, `-command-timeout 30s`, `-log-dir logs`, `-backup-dir backups`,
`-env-file .env`, `-known-hosts ""` (defaults to `~/.ssh/known_hosts` or `%USERPROFILE%\.ssh\known_hosts`), `-host-key-policy update`.

Key new flags:

| Flag | Default | Description |
|---|---|---|
| `-op` | `false` | Operational mode: run commands without configure/commit/save |
| `-output-dir DIR` | `""` | Write per-device output to `<dir>/<hostname>.txt` |
| `-json-report FILE` | `""` | Write a JSON run report to the given file path |
| `-rollback-on-fail` | `false` | Re-apply pre-change backup on failure (requires `-backup`) |
| `-strict-safety` | `true` | Abort before connecting on a `CRITICAL` lockout risk (`-force` accepts) or a destructive command (`-allow-dangerous` accepts) |
| `-allow-dangerous` | `false` | Accept intentionally destructive commands (`no router bgp`, `delete interfaces`, `clear ip bgp *`, ...) |
| `-commit-confirm MIN` | `0` | Arm an on-box deadman timer of MIN minutes; confirm only after verification (0 = off) |
| `-allow-reboot-rollback` | `false` | Permit `reload in MIN` as the deadman on classic IOS and Cisco ASA |
| `-verify-file FILE` | `""` | Post-change health checks (`!@verify` blocks in the commands file/template also count) |
| `-plan` | `false` | Show the risk / impact / rollback-safety matrix and ask `Proceed ...? [y/N]` (combine with `-dry-run`) |
| `-key-file` | `""` | Path to SSH private key file for device authentication (overrides `NETCONFIG_KEY_FILE`) |
| `-jump` | `true` | Master toggle for bastion / jump host routing (`-jump=false` to bypass) |
| `-jump-host` | `""` | Global default bastion `host[:port]` |
| `-jump-user` | `""` | SSH username for global bastion (overrides `NETCONFIG_JUMP_USERNAME`) |
| `-jump-password` | `""` | SSH password for global bastion (overrides `NETCONFIG_JUMP_PASSWORD`) |
| `-jump-key-file` | `""` | SSH private key file for global bastion (overrides `NETCONFIG_JUMP_KEY_FILE`) |
| `-mesh-fallback` | `false` | Attempt SSH jump tunneling through neighboring inventory devices if direct connection fails |

### Jump Host / Bastion Proxy (`-jump`, `-jump-host`)

Route SSH connections through an SSH jump host (bastion) using direct-tcpip tunneling (equivalent to OpenSSH `ProxyJump` / `-J`). Supports a hybrid configuration:

- **Global Bastion:** Pass via `-jump-host mgmt-gw:22` or configure `NETCONFIG_JUMP_HOST`, `NETCONFIG_JUMP_USERNAME`, `NETCONFIG_JUMP_PASSWORD` in `.env`.
- **Per-Device Bastion & Direct Override:** Add an optional 6th column `jump_host` in `inventory.csv` (`hostname,address,port,vendor,credential_group,jump_host`). Specific named bastions resolve credentials via `NETCONFIG_JUMP_<NAME>_HOST`, `_USERNAME`, `_PASSWORD`. Set to `direct`, `none`, or `-` to bypass the global bastion and connect directly (e.g. for devices reached over WireGuard or local LAN). Leaving it blank inherits the global bastion if configured, or connects directly if none is set.
- **Master Kill-Switch:** Disable all jump routing on demand with `-jump=false`.
- **Zero Configuration Impact:** When no jump host is configured, all devices connect directly with zero overhead or prompt.


## Layout

```
cmd/netconfig            flags, confirmation prompt, wiring, exit codes
internal/inventory       CSV parsing and filtering
internal/credentials     .env parsing, 3-tier resolution, terminal prompter
internal/vendor          per-vendor prompts, pagers, confirmations, errors, config-mode plans
                           + BuildOpPlan() for operational mode
internal/sshclient       dial/handshake/auth, PTY shell, expect loop, host key policies, SafeBuffer
internal/task            jobs, worker pool, backup, dry-run, rollback, per-device output, JSON report
internal/logging         console + file logger, secret masking
internal/backup          the backup engine: worker pool, change detection, diff, risk, retention,
                           console summary, browsing a backup tree
internal/redact          masks secrets in configuration text before it is saved
internal/compliance      golden-config baselines and drift
internal/report          HTML report, Markdown changelog, JSON/CSV, result table
internal/errcat          failure categories used in summaries and reports
```

`task` depends only on small interfaces (`Transport`, `Session`), so its tests run against a fake
device with no SSH involved. Panics are recovered per device, output buffers are mutex-protected
(`SafeBuffer`), and results are written per index with no shared state between workers.

## Verify before first use

```sh
gofmt -l cmd internal          # hand-formatted code; run `make fmt` once
go vet -mod=vendor ./...
make test
make test-race                 # needs cgo
```

Then try, in this order, against a lab device of each platform you use: `-dry-run`,
`-dry-run -verbose`, a one-device `-limit` run with `-backup`. Prompt patterns, pager markers and
error signatures live in `internal/vendor/vendor.go`; platforms and software versions vary, so
expect to adjust them (add a case to `vendor_test.go` for each tweak).
