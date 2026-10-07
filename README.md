# netconfig

Apply configuration commands to many network devices over SSH, concurrently, from a
single static binary. Built for air-gapped management networks: no runtime
dependencies, no network access other than SSH to the devices.

Supported platforms: Cisco IOS/IOS-XE, Juniper Junos, Huawei VRP, Fortinet FortiOS, Arista EOS, VyOS, Ruijie RGOS, Aruba AOS-CX/AOS-S, Check Point Gaia.

> **Status:** written without access to a Go toolchain or real devices. Nothing here has
> been compiled or run yet. Follow [Verify before first use](#verify-before-first-use)
> and test against lab devices before pointing it at production.

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

Fastest way:
```sh
make init
```
This automatically initializes `.env` (with `chmod 600`), `inventory.csv`, and `commands.txt` from `examples/` without overwriting existing files.

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
```

Templates (rendered once per device):

```sh
./bin/netconfig -template examples/config.tmpl -var ntp=10.0.0.1 -var syslog=10.0.0.2 -limit '@dc1' -backup
```

## Inventory

```csv
hostname,address,port,vendor,credential_group
core-sw1,10.10.0.11,22,cisco,dc1
edge-mx1,10.20.0.1,,junos,dc2
```

Header, blank lines and `#` comments are optional. Empty `port` means 22, empty
`credential_group` means `default`. Vendor accepts aliases (`ios`, `ios-xe`, `eos`, `juniper`,
`vrp`, `fortios`, `fortigate`, ...). All row errors are reported together with line numbers.
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
  run. `-dry-run` needs no confirmation.
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
  | Cisco, Huawei, FortiOS | no candidate configuration exists, so only connectivity/login/privilege and a read-only probe (`show clock`, `display clock`, `get system status`); the commands that *would* run are listed in the log but not sent |

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
| Junos | `configure` | `commit`, `exit` | `set cli screen-length 0` |
| Huawei VRP | `system-view` | `return`, `save` | `screen-length 0 temporary` |
| FortiOS | none (commands are `config ... end` blocks) | saved by each `end` | `--More--` is answered, nothing is changed on the device |
| Arista EOS | `configure terminal` | `end`, `write memory` | `terminal length 0` |

Commit/save/backup steps get 3x `-command-timeout`.

## Host keys

Default `-host-key-policy strict`: only hosts already in `-known-hosts` (default `./known_hosts`,
OpenSSH format) are accepted; unknown hosts fail with `HOSTKEY_FAILED` and a hint. Use
`accept-new` once to enroll devices on first contact (trust-on-first-use; a *changed* key is still
rejected), then go back to `strict`. `insecure` disables verification and logs a warning.
Old devices that only offer SHA-1 key exchange or CBC ciphers need `-legacy-algorithms`.

## Logging and results

Console (stderr, coloured on a terminal, `-no-color` / `NO_COLOR` to disable) and a timestamped file
`logs/netconfig-YYYYMMDD-HHMMSS.log` (mode 0600). The file always contains the exact command traces
(`>>`) and device responses (`<<`) per device, tagged `[hostname]`; the console shows them with
`-verbose`. Backup contents are written to the backup files, not to the log.

End-of-run table: host, address, vendor, status (SUCCEEDED / FAILED / SKIPPED), reason, time, detail,
followed by counts and the hosts per reason.

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
`-env-file .env`, `-known-hosts known_hosts`, `-host-key-policy strict`.

## Layout

```
cmd/netconfig            flags, confirmation prompt, wiring, exit codes
internal/inventory       CSV parsing and filtering
internal/credentials     .env parsing, 3-tier resolution, terminal prompter
internal/vendor          per-vendor prompts, pagers, confirmations, errors, config-mode plans
internal/sshclient       dial/handshake/auth, PTY shell, expect loop, host key policies, SafeBuffer
internal/task            jobs, worker pool, backup, dry-run, categorisation, summary
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
