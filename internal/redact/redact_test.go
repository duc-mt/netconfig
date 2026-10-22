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
