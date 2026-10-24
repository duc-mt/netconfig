// ==============================================================================
// File name:     commonflags.go
// Description:   Flags shared by the configuration runner and "backup".
// License:       MIT
// ==============================================================================
package main

import (
	"flag"
	"time"

	"netconfig/internal/memory"
)

// commonFlags are the flags that mean the same thing wherever netconfig
// connects to devices: which devices, how many at once, timeouts, credentials,
// host-key policy, jump hosts, route memory and the log. They are declared once
// here so the commands cannot drift apart in names, defaults or wording (they
// had: 30 flags were declared twice, and only 6 had the same help text).
type commonFlags struct {
	inventory string
	limit     string

	concurrency    int
	connectTimeout time.Duration
	commandTimeout time.Duration

	envFile string
	keyFile string
	logDir  string
	noColor bool

	knownHosts       string
	hostKeyPolicy    string
	updateKnownHosts bool
	replaceHostKeys  bool
	legacyAlgorithms bool
	tcpMSS           int

	jump         bool
	jumpHost     string
	jumpUser     string
	jumpPassword string
	jumpKeyFile  string
	meshFallback bool

	memory     bool
	memoryFile string
}

// register declares the flags on fs.
func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.inventory, "inventory", "inventory.csv", "inventory CSV: hostname,address,port,vendor,credential_group")
	fs.StringVar(&c.limit, "limit", "", "only these devices: comma-separated hostname globs, or @group")

	fs.IntVar(&c.concurrency, "concurrency", 10, "maximum number of devices processed at the same time")
	fs.DurationVar(&c.connectTimeout, "connect-timeout", 10*time.Second, "TCP connect + SSH handshake budget per device")
	fs.DurationVar(&c.commandTimeout, "command-timeout", 30*time.Second, "budget per command (commit/save/backup get 3x)")

	fs.StringVar(&c.envFile, "env-file", ".env", "credentials file (KEY=VALUE lines); missing is fine")
	fs.StringVar(&c.keyFile, "key-file", "", "path to an SSH private key file for device authentication (overrides NETCONFIG_KEY_FILE)")
	fs.StringVar(&c.logDir, "log-dir", "logs", "directory for the timestamped audit log file")
	fs.BoolVar(&c.noColor, "no-color", false, "disable coloured console output")

	fs.StringVar(&c.knownHosts, "known-hosts", "", "OpenSSH-format known_hosts file for host key checks (defaults to ~/.ssh/known_hosts or %USERPROFILE%\\.ssh\\known_hosts)")
	fs.StringVar(&c.hostKeyPolicy, "host-key-policy", "update", "policy for host keys: 'strict' (reject unknown/changed), 'accept-new' (learn new), or 'update' (learn new and replace changed keys)")
	fs.BoolVar(&c.updateKnownHosts, "update-known-hosts", false, "automatically remove mismatched existing keys and learn new keys in known_hosts (alias for -host-key-policy update)")
	fs.BoolVar(&c.replaceHostKeys, "replace-host-keys", false, "alias for -update-known-hosts")
	fs.BoolVar(&c.legacyAlgorithms, "legacy-algorithms", true, "allow negotiation of legacy SSH algorithms (3des-cbc, diffie-hellman-group1-sha1, ssh-dss) as fallback for older network gear")
	fs.IntVar(&c.tcpMSS, "tcp-mss", 1360, "TCP Maximum Segment Size for outgoing SSH sockets (0=OS default, >0=clamp MSS to avoid PMTU issues)")

	fs.BoolVar(&c.jump, "jump", true, "enable jump host / bastion routing (set false to connect all devices directly, overriding inventory and env config)")
	fs.StringVar(&c.jumpHost, "jump-host", "", "global default bastion host[:port] for devices not reachable directly (e.g. mgmt-gw.example.com:22)")
	fs.StringVar(&c.jumpUser, "jump-user", "", "SSH username for the global jump host (overrides NETCONFIG_JUMP_USERNAME)")
	fs.StringVar(&c.jumpPassword, "jump-password", "", "SSH password for the global jump host (overrides NETCONFIG_JUMP_PASSWORD; visible in the process list, prefer the environment)")
	fs.StringVar(&c.jumpKeyFile, "jump-key-file", "", "SSH private key file for the global jump host (overrides NETCONFIG_JUMP_KEY_FILE)")
	fs.BoolVar(&c.meshFallback, "mesh-fallback", false, "attempt SSH jump tunneling through neighboring inventory devices if direct connection fails (disabled by default; it routes credentials through other devices)")

	fs.BoolVar(&c.memory, "memory", true, "enable automatic memory of learned routing and fallback paths across runs")
	fs.StringVar(&c.memoryFile, "memory-file", memory.DefaultFile, "persistent memory file for learned device routes")
}
