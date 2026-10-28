// ==============================================================================
// File name:     defaults.go
// Description:   Built-in baseline rules.
// License:       MIT
// ==============================================================================
package audit

import "netops/internal/vendor"

// The built-in baseline is a starting point, written from each vendor's
// documented configuration syntax. A platform with no entry for a check is
// reported N/A rather than guessed at. Tune or replace it with a rules file
// (netconfig audit -print-defaults prints these as YAML to start from).

var (
	iosLike = []string{vendor.Cisco, vendor.CiscoASA, vendor.Arista, vendor.Ruijie, vendor.Aruba}
	ciscoVT = []string{vendor.Cisco, vendor.Ruijie}
)

func rule(id, title, sev string, vendors []string, block, require, forbid, remediation string) Rule {
	return Rule{ID: id, Title: title, Severity: sev, Vendors: append([]string(nil), vendors...),
		Block: block, Require: require, Forbid: forbid, Remediation: remediation}
}

func v(names ...string) []string { return names }

const (
	ipv4   = `\d{1,3}(?:\.\d{1,3}){3}`
	idleHW = `^\s*idle-timeout\s+(?:0\s+[1-9]\d*|[1-4]\s+\d+|5\s+0)\s*$`
)

func defaultRules() []Rule {
	const (
		ntp     = "ntp"
		syslog  = "syslog"
		telnet  = "telnet"
		snmp    = "snmp"
		vty     = "session-timeout"
		aaa     = "aaa"
		pwenc   = "password-encryption"
		httpSrv = "http-server"
		sshVer  = "ssh-version"
		banner  = "login-banner"

		tNTP    = "NTP server configured"
		tSyslog = "Remote syslog host configured"
		tTelnet = "Telnet disabled (SSH only)"
		tSNMP   = "No default SNMP communities (public/private)"
		tVTY    = "Idle session timeout of at most 5 minutes"
		tAAA    = "Centralised AAA (RADIUS/TACACS+) configured"
		tPwEnc  = "Passwords encrypted (service password-encryption, no type 0 secrets)"
		tHTTP   = "Unencrypted HTTP management server disabled"
		tSSH    = "SSH protocol version 2 only"
		tBanner = "Login warning banner configured"
	)
	return []Rule{
		// ---- NTP ----
		rule(ntp, tNTP, SevMedium, iosLike, "", `^\s*ntp server\s+\S+`, "", "Configure at least one NTP server: ntp server <address>"),
		rule(ntp, tNTP, SevMedium, v(vendor.CiscoSB), "", `^\s*sntp server\s+\S+`, "", "Configure SNTP: sntp server <address>"),
		rule(ntp, tNTP, SevMedium, v(vendor.Huawei), "", `^\s*ntp-service unicast-server\s+\S+`, "", "ntp-service unicast-server <address>"),
		rule(ntp, tNTP, SevMedium, v(vendor.Junos), "", `^set system ntp server\s+\S+`, "", "set system ntp server <address>"),
		rule(ntp, tNTP, SevMedium, v(vendor.Fortinet), `^config system ntp`, `^\s*set server\s+\S+`, "", "config system ntp / config ntpserver / edit 1 / set server <address>"),
		rule(ntp, tNTP, SevMedium, v(vendor.VyOS), "", `^set (?:system|service) ntp\b.*\bserver\b`, "", "set service ntp server <address>"),
		rule(ntp, tNTP, SevMedium, v(vendor.CheckPoint), "", `^set ntp server (?:primary|secondary)\s+\S+`, "", "set ntp server primary <address>"),
		rule(ntp, tNTP, SevMedium, v(vendor.PaloAlto), "", `\bntp-server-address\s+\S+`, "", "Device > Setup > Services: set a primary NTP server"),
		rule(ntp, tNTP, SevMedium, v(vendor.PfSense), "", `<timeservers>\S+</timeservers>`, "", "System > General Setup: set the time server"),

		// ---- syslog ----
		rule(syslog, tSyslog, SevMedium, v(vendor.Cisco, vendor.CiscoSB, vendor.CiscoASA, vendor.Arista, vendor.Ruijie, vendor.Aruba), "",
			`^\s*logging\s+(?:host|server)\s+\S+|^\s*logging\s+`+ipv4+`\b`, "", "Send logs to a collector: logging host <address>"),
		rule(syslog, tSyslog, SevMedium, v(vendor.Huawei), "", `^\s*info-center loghost\s+\S+`, "", "info-center loghost <address>"),
		rule(syslog, tSyslog, SevMedium, v(vendor.Junos), "", `^set system syslog host\s+\S+`, "", "set system syslog host <address> any notice"),
		rule(syslog, tSyslog, SevMedium, v(vendor.Fortinet), `^config log syslogd`, `^\s*set server\s+\S+`, "", "config log syslogd setting / set status enable / set server <address>"),
		rule(syslog, tSyslog, SevMedium, v(vendor.VyOS), "", `^set system syslog host\s+\S+`, "", "set system syslog host <address> facility all level notice"),
		rule(syslog, tSyslog, SevMedium, v(vendor.CheckPoint), "", `^add syslog log-remote-address\s+\S+`, "", "add syslog log-remote-address <address> level all"),
		rule(syslog, tSyslog, SevMedium, v(vendor.PfSense), "", `<remoteserver>\S+</remoteserver>`, "", "Status > System Logs > Settings: enable remote logging"),

		// ---- Telnet ----
		rule(telnet, tTelnet, SevHigh, ciscoVT, `^line vty`, `^\s*transport input ssh\s*$`, "", "On every vty line: transport input ssh"),
		rule(telnet, tTelnet, SevHigh, v(vendor.CiscoASA), "", "", `^telnet\s+`+ipv4, "Remove telnet access: no telnet <network> <mask> <interface>"),
		rule(telnet, tTelnet, SevHigh, v(vendor.CiscoSB), "", `^\s*no ip telnet server`, "", "no ip telnet server"),
		rule(telnet, tTelnet, SevHigh, v(vendor.Arista), `^management telnet`, "", `^\s*no shutdown\b`, "management telnet / shutdown"),
		rule(telnet, tTelnet, SevHigh, v(vendor.Huawei), `^user-interface vty`, `^\s*protocol inbound ssh\s*$`, "", "user-interface vty 0 4 / protocol inbound ssh"),
		rule(telnet, tTelnet, SevHigh, v(vendor.Junos), "", "", `^set system services telnet\b`, "delete system services telnet"),
		rule(telnet, tTelnet, SevHigh, v(vendor.Fortinet), "", "", `^\s*set admintelnet enable\b|^\s*set allowaccess\b.*\btelnet\b`, "Remove telnet from set allowaccess and set admintelnet disable"),
		rule(telnet, tTelnet, SevHigh, v(vendor.VyOS), "", "", `^set service telnet\b`, "delete service telnet"),
		rule(telnet, tTelnet, SevHigh, v(vendor.Aruba), "", "", `^\s*telnet server\b`, "no telnet server vrf <vrf>"),
		rule(telnet, tTelnet, SevHigh, v(vendor.CheckPoint), "", "", `^set net-access telnet on\b`, "set net-access telnet off"),

		// ---- SNMP ----
		rule(snmp, tSNMP, SevHigh, v(vendor.Cisco, vendor.CiscoSB, vendor.CiscoASA, vendor.Arista, vendor.Ruijie, vendor.Aruba), "", "",
			`^\s*snmp-server\b.*\bcommunity\s+(?:public|private)\b`, "Remove the default community: no snmp-server community public"),
		rule(snmp, tSNMP, SevHigh, v(vendor.Huawei), "", "", `^\s*snmp-agent community\s+(?:read|write)(?:\s+(?:cipher|simple))?\s+(?:public|private)\b`, "undo snmp-agent community <public|private>"),
		rule(snmp, tSNMP, SevHigh, v(vendor.Junos), "", "", `^set snmp community\s+(?:public|private)\b`, "delete snmp community public"),
		rule(snmp, tSNMP, SevHigh, v(vendor.Fortinet), `^config system snmp community`, "", `^\s*set name\s+"?(?:public|private)"?\s*$`, "Rename or delete the default SNMP community"),
		rule(snmp, tSNMP, SevHigh, v(vendor.VyOS), "", "", `^set service snmp community\s+'?(?:public|private)'?(?:\s|$)`, "delete service snmp community public"),
		rule(snmp, tSNMP, SevHigh, v(vendor.CheckPoint), "", "", `^set snmp community\s+(?:public|private)\b`, "delete snmp community public"),
		rule(snmp, tSNMP, SevHigh, v(vendor.PaloAlto), "", "", `\bsnmp-community-string\s+(?:public|private)\b`, "Use SNMPv3 or a non-default community"),
		rule(snmp, tSNMP, SevHigh, v(vendor.PfSense), "", "", `<(?:rocommunity|rwcommunity)>(?:public|private)</`, "Services > SNMP: change the community string"),

		// ---- idle session timeout ----
		rule(vty, tVTY, SevMedium, ciscoVT, `^line vty`, `^\s*exec-timeout\s+(?:0\s+[1-9]\d*|[1-4]\s+\d+|5\s+0)\s*$`, "", "On every vty line: exec-timeout 5 0"),
		rule(vty, tVTY, SevMedium, v(vendor.CiscoASA), "", `^ssh timeout\s+[1-5]\s*$`, "", "ssh timeout 5"),
		rule(vty, tVTY, SevMedium, v(vendor.Arista), `^management ssh`, `^\s*idle-timeout\s+[1-5]\s*$`, "", "management ssh / idle-timeout 5"),
		rule(vty, tVTY, SevMedium, v(vendor.Huawei), `^user-interface vty`, idleHW, "", "user-interface vty 0 4 / idle-timeout 5 0"),
		rule(vty, tVTY, SevMedium, v(vendor.Junos), "", `^set system login class\s+\S+\s+idle-timeout\s+[1-5]\s*$`, "", "set system login class <class> idle-timeout 5"),
		rule(vty, tVTY, SevMedium, v(vendor.Fortinet), "", `^\s*set admintimeout\s+[1-5]\s*$`, "", "config system global / set admintimeout 5"),
		rule(vty, tVTY, SevMedium, v(vendor.CheckPoint), "", `^set inactivity-timeout\s+[1-5]\s*$`, "", "set inactivity-timeout 5"),
		rule(vty, tVTY, SevMedium, v(vendor.PaloAlto), "", `\bidle-timeout\s+[1-5];`, "", "Device > Setup > Management: Idle Timeout 5"),

		// ---- AAA ----
		rule(aaa, tAAA, SevMedium, v(vendor.Cisco, vendor.CiscoSB, vendor.CiscoASA, vendor.Arista, vendor.Ruijie), "",
			`^\s*(?:tacacs-server|radius-server|tacacs server|radius server|aaa group server|aaa-server\s+\S+\s+protocol)\b`, "", "Define a TACACS+/RADIUS server and use it in the login method list"),
		rule(aaa, tAAA, SevMedium, v(vendor.Aruba), "", `^\s*(?:radius-server|tacacs-server)\s+host\b`, "", "radius-server host <address> / tacacs-server host <address>"),
		rule(aaa, tAAA, SevMedium, v(vendor.Huawei), "", `^\s*(?:hwtacacs-server template|radius-server template)\b`, "", "hwtacacs-server template <name>"),
		rule(aaa, tAAA, SevMedium, v(vendor.Junos), "", `^set system (?:radius-server|tacplus-server)\s+\S+`, "", "set system tacplus-server <address> secret <secret>"),
		rule(aaa, tAAA, SevMedium, v(vendor.Fortinet), `^config user (?:radius|tacacs\+)`, `^\s*edit\s+`, "", "config user tacacs+ / edit <name> / set server <address>"),
		rule(aaa, tAAA, SevMedium, v(vendor.VyOS), "", `^set system login (?:radius|tacacs)\b`, "", "set system login radius server <address> key <key>"),
		rule(aaa, tAAA, SevMedium, v(vendor.CheckPoint), "", `^add aaa (?:radius|tacacs)-servers\b`, "", "add aaa tacacs-servers priority 1 server <address> key <key>"),

		// ---- password storage ----
		// Only the platforms whose running configuration can hold readable
		// secrets are covered; the rest store them hashed by design (N/A).
		{ID: pwenc, Title: tPwEnc, Severity: SevHigh, Vendors: append([]string(nil), ciscoVT...),
			Require: `^\s*service password-encryption\s*$`, Forbid: `^\s*(?:enable password|username\s+\S+\s+password)\s+0\s+\S+`,
			Remediation: "service password-encryption; replace plaintext secrets with: enable secret <secret> / username <name> secret <secret>"},

		// ---- plain HTTP management ----
		rule(httpSrv, tHTTP, SevMedium, v(vendor.Cisco, vendor.CiscoSB, vendor.Ruijie), "", "", `^\s*ip http server\s*$`, "no ip http server (use ip http secure-server if a web UI is needed)"),
		rule(httpSrv, tHTTP, SevMedium, v(vendor.Huawei), "", "", `^\s*http server enable\b`, "undo http server enable"),
		rule(httpSrv, tHTTP, SevMedium, v(vendor.Junos), "", "", `^set system services web-management http\b`, "delete system services web-management http"),
		rule(httpSrv, tHTTP, SevMedium, v(vendor.Fortinet), "", "", `^\s*set allowaccess\b.*\bhttp\b`, "Remove http from set allowaccess on every interface"),

		// ---- SSH protocol version ----
		rule(sshVer, tSSH, SevMedium, ciscoVT, "", `^\s*ip ssh version 2\s*$`, "", "ip ssh version 2"),
		rule(sshVer, tSSH, SevMedium, v(vendor.CiscoASA), "", `^ssh version 2\s*$`, "", "ssh version 2"),
		rule(sshVer, tSSH, SevMedium, v(vendor.Huawei), "", "", `^\s*ssh server compatible-ssh1x\s+enable\b`, "undo ssh server compatible-ssh1x enable"),
		rule(sshVer, tSSH, SevMedium, v(vendor.Junos), "", "", `^set system services ssh protocol-version v1\b`, "delete system services ssh protocol-version v1"),
		rule(sshVer, tSSH, SevMedium, v(vendor.Fortinet), "", "", `^\s*set admin-ssh-v1\s+enable\b`, "config system global / set admin-ssh-v1 disable"),

		// ---- legal / login banner ----
		rule(banner, tBanner, SevLow, v(vendor.Cisco, vendor.CiscoSB, vendor.CiscoASA, vendor.Arista, vendor.Ruijie, vendor.Aruba), "", `^\s*banner\s+(?:login|motd|exec)\b`, "", "banner login <delimiter> authorised use only <delimiter>"),
		rule(banner, tBanner, SevLow, v(vendor.Huawei), "", `^\s*header\s+(?:login|shell)\b`, "", "header login information \"authorised use only\""),
		rule(banner, tBanner, SevLow, v(vendor.Junos), "", `^set system login (?:message|announcement)\b`, "", "set system login message \"authorised use only\""),
		rule(banner, tBanner, SevLow, v(vendor.Fortinet), "", `^\s*set pre-login-banner\s+enable\b`, "", "config system global / set pre-login-banner enable"),
		rule(banner, tBanner, SevLow, v(vendor.VyOS), "", `^set system login banner (?:pre|post)-login\b`, "", "set system login banner pre-login '<text>'"),
		rule(banner, tBanner, SevLow, v(vendor.CheckPoint), "", `^set message banner on\b`, "", "set message banner on"),
	}
}

// Defaults returns the compiled built-in baseline.
func Defaults() []Rule {
	rules := defaultRules()
	if err := Compile(rules); err != nil {
		panic("audit: built-in rules do not compile: " + err.Error()) // covered by tests
	}
	return rules
}
