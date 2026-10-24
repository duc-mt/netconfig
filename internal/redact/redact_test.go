// ==============================================================================
// Package main implements Implementation and logic for redact_test..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run redact_test.go [options]
// Notes:         Go package implementation
// ==============================================================================
package redact

import (
	"fmt"
	"strings"
	"testing"
)

func TestRedactConfig(t *testing.T) {
	input := `! Cisco IOS
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKXqk1
username admin privilege 15 secret 9 $9$jK8...
username backup password 7 08324F5E1A
snmp-server community public RO
snmp-server community private RW
crypto isakmp key mySecretKey123 address 192.168.1.1

! Juniper
set system root-authentication encrypted-password "$6$rounds=10000$..."
set snmp community "public" {
set security ike proposal p1 pre-shared-secret "$9$..."
set protocols bgp group PEER neighbor 10.0.0.2 authentication-key "junosBgpSecret"

! Fortinet
set password ENC 1234567890
set preshared-key my-ipsec-psk
set psksecret ENC fortiPskSecret123
set auth-psk "fortiAuthPskSecret"
set community-name "fortiSnmpSecret"

! Routing Protocols & Check Point
neighbor 10.1.1.2 password ciscoBgpSecretPass
ip ospf message-digest-key 1 md5 ospfMd5SecretPass
set user admin password-hash $1$gaia$99887766554433221100
password plaintext arubaSecretPass

! TACACS & RADIUS
tacacs-server key 7 secretTacacsPass
radius-server host 10.1.1.1 key radiusSecretPass

! SNMPv3
snmp-server user admin network-admin v3 auth sha MyAuthPass123 priv aes 128 MyPrivPass456

! VyOS SNMP & User Login
set service snmp community vyosCommunityRO client 10.0.0.0/8
set system login user netadmin authentication encrypted-password '$6$rounds=5000$vyosSecretHash'
set system login user netadmin level 'admin'

! Private Key
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y...
-----END RSA PRIVATE KEY-----
`

	redacted := Config(input)

	forbidden := []string{
		"$1$mERr$hx5rVt7rPNoS4wqbXKXqk1",
		"08324F5E1A",
		"public",
		"private",
		"mySecretKey123",
		"MIIEowIBAAKCAQEA0Y...",
		"1234567890",
		"my-ipsec-psk",
		"fortiPskSecret123",
		"fortiAuthPskSecret",
		"fortiSnmpSecret",
		"secretTacacsPass",
		"radiusSecretPass",
		"MyAuthPass123",
		"MyPrivPass456",
		"vyosCommunityRO",
		"$6$rounds=5000$vyosSecretHash",
		"junosBgpSecret",
		"ciscoBgpSecretPass",
		"ospfMd5SecretPass",
		"$1$gaia$99887766554433221100",
		"arubaSecretPass",
	}

	for _, str := range forbidden {
		if strings.Contains(redacted, str) {
			t.Errorf("expected string %q to be redacted, but found in output:\n%s", str, redacted)
		}
	}

	if !strings.Contains(redacted, "set system login user netadmin level 'admin'") {
		t.Errorf("expected subsequent commands to be preserved, but missing from output:\n%s", redacted)
	}

	if !strings.Contains(redacted, "<REDACTED>") {
		t.Errorf("expected <REDACTED> marker in output, got:\n%s", redacted)
	}
}

func TestRedactMikroTik(t *testing.T) {
	input := strings.Join([]string{
		"/ppp secret",
		"add name=vpnuser password=PppSecretPass123 profile=default service=l2tp",
		"/interface wireless security-profiles",
		`set [ find default=yes ] authentication-types=wpa2-psk mode=dynamic-keys wpa2-pre-shared-key=WifiWpa2Secret wpa-pre-shared-key="Wifi Wpa Secret With Spaces" supplicant-identity=MikroTik`,
		"/ip ipsec identity",
		"add peer=peer1 secret=IpsecSecret!42",
		"/interface eoip",
		"add ipsec-secret=EoipIpsecSecret name=eoip1 remote-address=10.9.9.9",
		"/snmp community",
		"set [ find default=yes ] authentication-password=SnmpAuthPass encryption-password=SnmpPrivPass security=private",
		"/radius",
		"add address=10.0.0.5 secret=RadiusSharedSecret service=login",
		"/routing bgp peer",
		"add name=p1 remote-address=10.1.1.1 remote-as=65001 tcp-md5-key=BgpMd5Key",
		"/interface wireguard",
		`add listen-port=13231 name=wg1 private-key="WgPrivateKeyBase64+/=="`,
		"/interface wireguard peers",
		`add allowed-address=10.9.0.2/32 interface=wg1 preshared-key="WgPresharedKey==" public-key="WgPublicKey=="`,
		"/interface wifi security",
		"add authentication-types=wpa2-psk name=sec1 passphrase=WifiPassphrase99",
		"/tool e-mail",
		"set password=MailPass user=alert@example.com",
		"/interface ovpn-client",
		`add connect-to=1.2.3.4 name=ovpn1 password="Ovpn Pass \"quoted\" tail" user=vpn1`,
		`add connect-to=1.2.3.5 name=ovpn2 password="" user=vpn2`,
		"/system identity",
		"set name=rtr1",
	}, "\n")

	got := Config(input)

	for _, secret := range []string{
		"PppSecretPass123", "WifiWpa2Secret", "Wifi Wpa Secret With Spaces", "IpsecSecret!42",
		"EoipIpsecSecret", "SnmpAuthPass", "SnmpPrivPass", "RadiusSharedSecret", "BgpMd5Key",
		"WgPrivateKeyBase64", "WgPresharedKey", "WifiPassphrase99", "MailPass", "Ovpn Pass", "tail",
	} {
		if strings.Contains(got, secret) {
			t.Errorf("secret %q leaked:\n%s", secret, got)
		}
	}

	// Everything that is not a secret must survive, including the rest of each line.
	for _, keep := range []string{
		"add name=vpnuser password=\"<REDACTED>\" profile=default service=l2tp",
		"authentication-types=wpa2-psk mode=dynamic-keys",
		"supplicant-identity=MikroTik",
		"add peer=peer1 secret=\"<REDACTED>\"",
		"name=eoip1 remote-address=10.9.9.9",
		"security=private",
		"remote-as=65001",
		"listen-port=13231 name=wg1",
		`public-key="WgPublicKey=="`,
		"user=alert@example.com",
		`user=vpn1`,
		`password="" user=vpn2`, // an empty password is not a secret and is left alone
		"/ppp secret",           // menu path, not a parameter
		"set name=rtr1",
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("expected %q to be preserved, got:\n%s", keep, got)
		}
	}
}

func TestRedactCiscoASA(t *testing.T) {
	input := strings.Join([]string{
		": Saved",
		"ASA Version 9.12(4)",
		"hostname asa1",
		"passwd 2KFQnbNIdI.2KYOU encrypted",
		"enable password 8Ry2YjIyt7RRXU24 encrypted",
		"username admin password $sha512$5000$abcDEF123== pbkdf2 privilege 15",
		"ssh version 2",
		": end",
	}, "\n")

	got := Config(input)

	for _, secret := range []string{"2KFQnbNIdI.2KYOU", "8Ry2YjIyt7RRXU24", "$sha512$5000$abcDEF123=="} {
		if strings.Contains(got, secret) {
			t.Errorf("secret %q leaked:\n%s", secret, got)
		}
	}
	for _, keep := range []string{"passwd <REDACTED> encrypted", "hostname asa1", "ssh version 2", ": end"} {
		if !strings.Contains(got, keep) {
			t.Errorf("expected %q to be preserved, got:\n%s", keep, got)
		}
	}
}

func TestRedactNewRulesAreIdempotent(t *testing.T) {
	input := "add name=u password=Secret1 secret=\"two words\"\npasswd abcdef encrypted\n"
	once := Config(input)
	if twice := Config(once); twice != once {
		t.Errorf("redaction is not idempotent:\n once: %q\ntwice: %q", once, twice)
	}
}

// Forms where the secret is not the first token after the keyword: a
// privilege level ("enable password level 15 encrypted <hash>"), an
// "encrypted" marker (Small Business), or a vendor keyword in front
// ("ikev1 pre-shared-key", "failover key", "snmp-server host ... community").
// Masking the wrong token leaves the real secret in the saved backup file.
func TestRedactMultiTokenSecrets(t *testing.T) {
	cases := []struct{ in, want, secret string }{
		// Small Business
		{"username cisco password encrypted 6b3c7f1a2d4e5f60718293a4b5c6d7e8 privilege 15",
			"username cisco password encrypted <REDACTED> privilege 15", "6b3c7f1a2d4e5f60"},
		{"enable password level 15 encrypted 7f1a2d4e5f60718293a4b5c6d7e8aabb",
			"enable password level 15 encrypted <REDACTED>", "7f1a2d4e5f60"},
		{"radius-server key encrypted 9a8b7c6d5e4f30211234567890abcdef",
			"radius-server key encrypted <REDACTED>", "9a8b7c6d5e4f"},
		// classic IOS
		{"enable password level 15 7 0822455D0A16",
			"enable password level 15 7 <REDACTED>", "0822455D0A16"},
		{"enable secret level 10 5 $1$abcd$XyZ123hashvalue",
			"enable secret level 10 5 <REDACTED>", "XyZ123hashvalue"},
		{"snmp-server host 10.0.0.1 version 2c S3cretIOS",
			"snmp-server host 10.0.0.1 version 2c <REDACTED>", "S3cretIOS"},
		// ASA
		{" ikev1 pre-shared-key S3cretPSK", " ikev1 pre-shared-key <REDACTED>", "S3cretPSK"},
		{" ikev2 local-authentication pre-shared-key S3cretL", " ikev2 local-authentication pre-shared-key <REDACTED>", "S3cretL"},
		{" ikev2 remote-authentication pre-shared-key 0 S3cretR", " ikev2 remote-authentication pre-shared-key 0 <REDACTED>", "S3cretR"},
		{"failover key S3cretFO", "failover key <REDACTED>", "S3cretFO"},
		{"failover ipsec pre-shared-key S3cretFI", "failover ipsec pre-shared-key <REDACTED>", "S3cretFI"},
		{"snmp-server host inside 10.0.0.1 community S3cretCOMM",
			"snmp-server host inside 10.0.0.1 community <REDACTED>", "S3cretCOMM"},
		{" ldap-login-password S3cretLDAP", " ldap-login-password <REDACTED>", "S3cretLDAP"},
		{" radius-common-pw S3cretRAD", " radius-common-pw <REDACTED>", "S3cretRAD"},
		// a key that merely starts with a type digit must not keep that digit
		{"key 7abcdef", "key <REDACTED>", "7abcdef"},
		// unchanged behaviour
		{"enable password 8Ry2YjIyt7RRXU24 encrypted", "enable password <REDACTED> encrypted", "8Ry2YjIyt7RRXU24"},
		{"username admin password $sha512$5000$abc== pbkdf2 privilege 15",
			"username admin password <REDACTED> pbkdf2 privilege 15", "abc=="},
		{"passwd 2KFQnbNIdI.2KYOU encrypted", "passwd <REDACTED> encrypted", "2KFQnbNIdI"},
		{"crypto isakmp key 0 mySecret address 192.168.1.1", "crypto isakmp key 0 <REDACTED> address 192.168.1.1", "mySecret"},
		{"snmp-server host 10.0.0.1 version 3 priv monitor", "snmp-server host 10.0.0.1 version 3 priv monitor", ""},
		{"ntp server 10.0.0.9", "ntp server 10.0.0.9", ""},
		{"hostname asa1", "hostname asa1", ""},
	}
	for _, c := range cases {
		got := Config(c.in)
		if got != c.want {
			t.Errorf("Config(%q)\n got  %q\n want %q", c.in, got, c.want)
		}
		if c.secret != "" && strings.Contains(got, c.secret) {
			t.Errorf("Config(%q) leaks %q: %q", c.in, c.secret, got)
		}
		if again := Config(got); again != got {
			t.Errorf("Config is not idempotent on %q: %q", c.in, again)
		}
	}
}

// configWholeText is the original implementation: every rule over the whole
// text. It is slow on large configurations (the regexp library falls back to
// its general engine for long inputs) but it is the reference for what must be
// masked, so Config's faster line-by-line form is checked against it.
func configWholeText(content string) string {
	result := content
	for _, rule := range commonPatterns {
		result = rule.re.ReplaceAllString(result, rule.repl)
	}
	return result
}

// differentialCorpus is every secret-bearing form the tests know about, in
// realistic surroundings, with line endings that real devices produce.
func differentialCorpus() []string {
	secrets := []string{
		"username admin password $sha512$5000$abcDEF123== pbkdf2 privilege 15",
		"username cisco password encrypted 6b3c7f1a2d4e5f60718293a4b5c6d7e8 privilege 15",
		"username bob secret 9 $9$abcdefghijkl",
		"enable secret 5 $1$abcd$XyZ123hashvalue",
		"enable password level 15 encrypted 7f1a2d4e5f60718293a4b5c6d7e8aabb",
		"enable password level 15 7 0822455D0A16",
		"enable password 8Ry2YjIyt7RRXU24 encrypted",
		"passwd 2KFQnbNIdI.2KYOU encrypted",
		" ldap-login-password S3cretLDAP",
		" radius-common-pw S3cretRAD",
		" ikev1 pre-shared-key S3cretPSK",
		" ikev2 remote-authentication pre-shared-key 0 S3cretR",
		"failover key S3cretFO",
		"crypto isakmp key 0 mySecret address 192.168.1.1",
		"key 7abcdef",
		"snmp-server community public RO",
		"snmp-server community S3cretSB ro view Default",
		"snmp-server host inside 10.0.0.1 community S3cretCOMM",
		"snmp-server host 10.0.0.1 version 2c S3cretIOS",
		"radius-server key encrypted 9a8b7c6d5e4f30211234567890abcdef",
		"tacacs-server host 10.0.0.5 key 7 0822455D0A16",
		"ntp authentication-key 1 md5 S3cretNTP",
		"ip ospf message-digest-key 1 md5 S3cretOSPF",
		"neighbor 10.0.0.2 password S3cretBGP",
		" snmp-server user monitor grp v3 auth sha S3cretAUTH priv aes 128 S3cretPRIV",
		"set system root-authentication encrypted-password \"$6$abc$def\"",
		"set service snmp community S3cretVyOS authorization ro",
		"set community-name \"S3cretFG\"",
		"set psksecret ENC S3cretFortiENC",
		"set password ENC S3cretFortiPW",
		"set user admin password-hash S3cretHash",
		"snmp-agent community read cipher S3cretVRP",
		"/snmp community set [ find default=yes ] name=S3cretMT",
		"/ppp secret add name=u password=\"S3cret MT\" service=any",
		"    community public {",
		"banner motd ^C password is not on this line ^C",
		// one line for each keyword alternative the rules know, with as few other
		// trigger words as possible, so the pre-check cannot hide behind them
		" preshared-key S3cretPS1",
		"set preshared-key S3cretFG1",
		"set private-key S3cretFG2",
		"set auth-psk S3cretFG3",
		"set psksecret S3cretFG4",
		"pre-shared-secret \"S3cretJ1\"",
		"md5 S3cretMD5only",
		"cipher cipher S3cretHW",
		"isis password S3cretISIS",
		"  auth sha-256 S3cretA256",
		"  auth sha-384 S3cretA384",
		"  auth sha-512 S3cretA512",
		"  auth md5 S3cretAMD5",
		"  priv des S3cretPDES",
		"  priv 3des S3cretP3DES",
		"  priv aes-128 S3cretP128",
		"  priv aes-192 S3cretP192",
		"  priv aes-256 S3cretP256",
		"/interface wireless security-profiles set [ find default=yes ] passphrase=S3cretPH",
		"/interface wireless security-profiles set [ find default=yes ] wpa-pre-shared-key=S3cretW1",
		"/interface wireless security-profiles set [ find default=yes ] wpa2-pre-shared-key=S3cretW2",
		"/interface wireless security-profiles set [ find default=yes ] private-pre-shared-key=S3cretW3",
		"/routing bgp peer set tcp-md5-key=S3cretBGP",
		"/ip ipsec identity add secret=S3cretIPSEC",
		"/ip ipsec identity add pre-shared-key=S3cretIPS2",
		"/ip ipsec identity add preshared-key=S3cretIPS3",
		"/snmp community set [ find default=yes ] authentication-password=S3cretSNMPA",
		"/snmp community set [ find default=yes ] encryption-password=S3cretSNMPE",
		"/snmp community set [ find default=yes ] authentication-key=S3cretSNMPK",
		"/system watchdog set management-protection-key=S3cretMPK",
		"/certificate set private-key=S3cretPK",
		"snmp-agent community write cipher S3cretVRPW",
		"hostname asa1", "ntp server 10.0.0.9", "interface Gi0/1", " description my password policy", "!", "end", "",
	}
	endings := []string{"\n", "\r\n"}
	var out []string
	for _, e := range endings {
		for _, s := range secrets {
			out = append(out, s+e)                        // alone
			out = append(out, "hostname x"+e+s+e+"end"+e) // between lines
			out = append(out, s)                          // no trailing newline
			out = append(out, "!"+e+s+e+s+e)              // repeated
			out = append(out, "  "+s+e+"\t"+s+e)          // indented
			out = append(out, strings.ToUpper(s)+e+s+e)   // case
		}
	}
	// everything at once, and a private key block among ordinary lines
	out = append(out, strings.Join(secrets, "\n")+"\n")
	out = append(out, "hostname x\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabcdef\n-----END RSA PRIVATE KEY-----\nenable secret 5 $1$abcd$XyZ\nend\n")
	out = append(out, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")
	out = append(out, "no key block here\nkey-ish\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	return out
}

// Config must mask exactly what the whole-text reference masks.
func TestConfigMatchesTheWholeTextReference(t *testing.T) {
	for i, in := range differentialCorpus() {
		if got, want := Config(in), configWholeText(in); got != want {
			t.Errorf("case %d differs from the reference for %q\n got  %q\n want %q", i, in, got, want)
		}
	}
}

func TestConfigIsExactOnLargeGeneratedConfigurations(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "interface GigabitEthernet0/%d\n description uplink-%d\n switchport access vlan %d\n!\n", i, i, 10+i%40)
		if i%9 == 0 {
			fmt.Fprintf(&b, "username user%d password encrypted %032x privilege 15\n", i, i*7919)
		}
		if i%13 == 0 {
			fmt.Fprintf(&b, "snmp-server community comm%d RO\nenable password level 15 7 0822455D0A%02d\n", i, i%100)
		}
		if i%31 == 0 {
			fmt.Fprintf(&b, " ikev1 pre-shared-key psk%d\nfailover key fo%d\n", i, i)
		}
	}
	cfg := b.String()
	got := Config(cfg)
	if want := configWholeText(cfg); got != want {
		t.Fatal("the line-by-line result differs from the whole-text reference on a large configuration")
	}
	for _, leaked := range []string{"comm9 ", "psk0", "fo31", "0822455D0A13"} {
		if strings.Contains(got, leaked) {
			t.Errorf("%q survived redaction", leaked)
		}
	}
}

// ---- the cheap pre-check that lets ordinary lines skip every rule ----------

// corpusLines are all lines of the differential corpus, in several cases.
func corpusLines() []string {
	var lines []string
	for _, c := range differentialCorpus() {
		for _, l := range strings.Split(c, "\n") {
			l = strings.TrimRight(l, "\r")
			lines = append(lines, l, strings.ToUpper(l), strings.ToLower(l), " "+l)
		}
	}
	return lines
}

func anyLineRuleMatches(line string) bool {
	for _, r := range lineRules {
		if r.re.MatchString(line) {
			return true
		}
	}
	return false
}

// The gate is only an optimisation: it must never hide a line that a rule
// would have masked, or a secret reaches the disk.
func TestTheGateNeverHidesALineARuleWouldMask(t *testing.T) {
	for _, line := range corpusLines() {
		if anyLineRuleMatches(line) && !mayHoldSecret(line) {
			t.Errorf("the gate would skip %q, which a rule masks", line)
		}
	}
}

// ...and the test above proves nothing unless every rule is exercised by it.
func TestEveryLineRuleHasACorpusExample(t *testing.T) {
	lines := corpusLines()
	for i, r := range lineRules {
		found := false
		for _, l := range lines {
			if r.re.MatchString(l) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("rule %d has no example line in the corpus: add one\n  %s", i, r.re)
		}
	}
}

func TestTheGateSkipsOrdinaryLines(t *testing.T) {
	for _, line := range []string{
		"interface GigabitEthernet0/1", " description uplink to core", " switchport mode access",
		" switchport access vlan 20", "ip address 10.0.0.1 255.255.255.0", "ntp server 10.0.0.9",
		"passive-interface GigabitEthernet0/2", "vlan 10", " name users", "hostname core-sw1", "!", "end", "",
		"spanning-tree mode rapid-pvst", "ip route 0.0.0.0 0.0.0.0 10.0.0.254",
	} {
		if mayHoldSecret(line) {
			t.Errorf("an ordinary line takes the slow path: %q", line)
		}
	}
}

// Go's case-insensitive matching folds more than ToLower does ("ſ" matches "s",
// the Kelvin sign matches "k"). Lines with any non-ASCII byte are rare, so they
// simply always take the full path.
func TestTheGateIsConservativeForNonASCII(t *testing.T) {
	for _, line := range []string{"ſecret 5 abc", "enable ſecret 5 $1$abcd$XyZ", "\u212Aey S3cret", "banner motd ü"} {
		if !mayHoldSecret(line) {
			t.Errorf("non-ASCII line must not be skipped: %q", line)
		}
	}
	for _, line := range []string{"enable ſecret 5 $1$abcd$XyZ123hashvalue", "ſnmp-server community public"} {
		if want := configWholeText(line); Config(line) != want {
			t.Errorf("Config(%q) = %q, reference %q", line, Config(line), want)
		}
	}
}

// ruleKeywords is the vocabulary of the line rules, one entry per alternative
// (the "passphrase=" in a MikroTik rule is a different thing to guard than the
// "password" of an IOS one). Each needs a corpus line that is really masked, so
// the gate test above cannot pass just because another keyword on a similar
// line triggers the same stem.
var ruleKeywords = []string{
	"password", "secret", "snmp-server community", "snmp-server host", "community", "isakmp key",
	"pre-shared-key", "preshared-key", "ikev1", "ikev2", "failover", "encrypted-password",
	"pre-shared-secret", "authentication-key", "md5", "private-key", "psksecret", "auth-psk",
	"password-hash", "neighbor", "message-digest-key", "isis password", "cipher", "tacacs-server",
	"radius-server", "tacacs", "radius", "auth sha-256", "auth sha-384", "auth sha-512", "auth sha ",
	"auth md5", "priv des", "priv 3des", "priv aes-128", "priv aes-192", "priv aes-256", "priv aes ",
	"set service snmp community", "community-name", "passphrase=", "wpa-pre-shared-key=",
	"wpa2-pre-shared-key=", "private-pre-shared-key=", "authentication-password=",
	"encryption-password=", "authentication-key=", "tcp-md5-key=", "private-key=",
	"management-protection-key=", "passwd", "ldap-login-password", "radius-common-pw", "secret=",
	"password=", "pre-shared-key=", "preshared-key=",
}

func TestEveryRuleKeywordHasAMaskedExample(t *testing.T) {
	lines := corpusLines()
	for _, kw := range ruleKeywords {
		found := false
		for _, l := range lines {
			if strings.Contains(strings.ToLower(l), kw) && anyLineRuleMatches(l) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no corpus line that a rule masks contains %q: add one to differentialCorpus", kw)
		}
	}
}
