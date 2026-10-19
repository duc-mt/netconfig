# netconfig

Apply configuration commands to many network devices over SSH, concurrently, from a
single static binary. Built for air-gapped management networks: no runtime
dependencies, no network access other than SSH to the devices.

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
`asa`, `ftd`) is rated `REBOOT ONLY`, like classic IOS.

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
  not touched (`BACKUP_FAILED`).
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
| Cisco Small Business (SF/SG/CBS) | `configure terminal` | `end`, `write memory` | `terminal datadump`, then `terminal length 0` (a device rejects the one its firmware lacks); the save prompt `Overwrite file [startup-config].... (Y/N)[N] ?` is answered `Y`; a backup may end in `exit` instead of `end` |
| Cisco ASA | `configure terminal` | `end`, `write memory` | `terminal pager 0`; a backup ends in `: end`; rejections are printed as `ERROR: ...` |
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
- **Per-Device Bastion:** Add an optional 6th column `jump_host` in `inventory.csv` (`hostname,address,port,vendor,credential_group,jump_host`). Specific named bastions resolve credentials via `NETCONFIG_JUMP_<NAME>_HOST`, `_USERNAME`, `_PASSWORD`.
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
