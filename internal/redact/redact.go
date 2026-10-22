// ==============================================================================
// Package main implements Implementation and logic for redact..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run redact.go [options]
// Notes:         Go package implementation
// ==============================================================================
// Package redact provides sensitive data sanitization for network device
// configurations, masking passwords, hashes, pre-shared keys, and SNMP
// community strings before saving configurations to disk.
package redact

import (
	"regexp"
)

type patternRule struct {
	re   *regexp.Regexp
	repl string
}

var commonPatterns = []patternRule{
	// Private key blocks (RSA, EC, OPENSSH, etc.)
	{
		re:   regexp.MustCompile(`(?s)-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----.*?-----END[ A-Z0-9_-]*PRIVATE KEY-----`),
		repl: "-----BEGIN PRIVATE KEY-----\n<REDACTED>\n-----END PRIVATE KEY-----",
	},
	// Cisco / IOS-XE / Ruijie / Aruba password and secret definitions
	{
		re:   regexp.MustCompile(`(?i)(?m)(^\s*(?:username\s+\S+(?:\s+privilege\s+\d+)?\s+)?(?:enable\s+)?(?:password|secret)(?:\s+level\s+\d+)?(?:\s+(?:\d+|plaintext|hash|ciphertext|encrypted))?)\s+\S+`),
		repl: "${1} <REDACTED>",
	},
	// Cisco / Network SNMP community strings
	{
		re:   regexp.MustCompile(`(?i)(?m)(^\s*snmp-server\s+community)\s+\S+(.*)`),
		repl: "${1} <REDACTED>${2}",
	},
	// SNMP trap/inform receivers carry the community inline:
	// "snmp-server host inside 10.0.0.1 community <string>" (ASA) and
	// "snmp-server host 10.0.0.1 version 2c <string>" (IOS).
	{
		re:   regexp.MustCompile(`(?i)(?m)(^[ \t]*snmp-server[ \t]+host[ \t]+(?:\S+[ \t]+)*?(?:community|version[ \t]+(?:1|2c))[ \t]+)\S+`),
		repl: "${1}<REDACTED>",
	},
	// IPsec / VPN pre-shared keys (Cisco, Check Point, etc.), including the ASA
	// forms "ikev1 pre-shared-key", "ikev2 local-authentication pre-shared-key"
	// and "failover key"
	{
		re:   regexp.MustCompile(`(?i)(?m)(^\s*(?:(?:ikev1|ikev2\s+(?:local|remote)-authentication|failover(?:\s+ipsec)?)\s+)?(?:crypto\s+isakmp\s+key|pre-shared-key|preshared-key|key)(?:\s+(?:0|5|6|7)\b)?)\s+\S+`),
		repl: "${1} <REDACTED>",
	},
	// Juniper Junos & VyOS encrypted passwords & secrets
	{
		re:   regexp.MustCompile(`(?i)(?m)(encrypted-password|pre-shared-secret|authentication-key|md5)\s+['"]?[^'";\r\n]+['"]?`),
		repl: `${1} "<REDACTED>"`,
	},
	// Juniper SNMP communities
	{
		re:   regexp.MustCompile(`(?i)(?m)(community\s+)"?[^";{\s]+"?(\s*\{)`),
		repl: `${1}"<REDACTED>"${2}`,
	},
	// FortiOS passwords, pre-shared keys and psksecret (IPsec phase1)
	{
		re:   regexp.MustCompile(`(?i)(?m)(^\s*set\s+(?:password|secret|preshared-key|pre-shared-key|private-key|psksecret|auth-psk)(?:\s+ENC)?)\s+\S+`),
		repl: `${1} "<REDACTED>"`,
	},
	// Check Point Gaia password-hash
	{
		re:   regexp.MustCompile(`(?i)(?m)(^\s*set\s+user\s+\S+\s+password-hash)\s+\S+`),
		repl: `${1} <REDACTED>`,
	},
	// Routing protocol authentication (BGP neighbor password, OSPF authentication/message-digest-key, ISIS password)
	{
		re:   regexp.MustCompile(`(?i)(?m)(^\s*(?:neighbor\s+\S+\s+password|ip\s+ospf\s+authentication-key|ip\s+ospf\s+message-digest-key\s+\d+\s+md5|isis\s+password))\s+\S+`),
		repl: `${1} <REDACTED>`,
	},
	// Huawei VRP cipher passwords / communities
	{
		re:   regexp.MustCompile(`(?i)(?m)(^\s*(?:password|cipher|snmp-agent community (?:read|write)))\s+cipher\s+\S+`),
		repl: `${1} cipher <REDACTED>`,
	},
	// TACACS+ and RADIUS server keys
	{
		re:   regexp.MustCompile(`(?i)(?m)(^\s*(?:tacacs-server|radius-server|tacacs|radius)(?:(?:\s+\S+)*?\s+key(?:\s+(?:\d+|encrypted))?))\s+\S+`),
		repl: "${1} <REDACTED>",
	},
	// SNMPv3 auth and priv credentials
	{
		re:   regexp.MustCompile(`(?i)(\bauth\s+(?:md5|sha|sha-256|sha-384|sha-512)\s+)\S+`),
		repl: "${1}<REDACTED>",
	},
	{
		re:   regexp.MustCompile(`(?i)(\bpriv\s+(?:des|3des|aes|aes-128|aes-192|aes-256)(?:\s+\d+)?\s+)\S+`),
		repl: "${1}<REDACTED>",
	},
	// VyOS SNMP community strings
	{
		re:   regexp.MustCompile(`(?i)(?m)(^\s*set\s+service\s+snmp\s+community\s+)\S+(.*)`),
		repl: "${1}<REDACTED>${2}",
	},
	// FortiOS SNMP community strings
	{
		re:   regexp.MustCompile(`(?i)(?m)(^\s*set\s+community-name\s+)"?[^"\r\n]+"?`),
		repl: `${1}"<REDACTED>"`,
	},
	// MikroTik RouterOS key=value secrets (PPP / VPN / Wi-Fi / SNMP / RADIUS /
	// BGP / WireGuard ...). The value is either a quoted string (with \"
	// escapes) or a bare token; an empty value ("") is not a secret and is kept.
	{
		re:   regexp.MustCompile(`(?i)(?m)(\b(?:password|secret|passphrase|(?:wpa2?-|private-)?pre-shared-key|preshared-key|authentication-password|encryption-password|authentication-key|tcp-md5-key|private-key|management-protection-key)=)(?:"(?:[^"\\\r\n]|\\.)+"|[^"\s]\S*)`),
		repl: `${1}"<REDACTED>"`,
	},
	// Cisco ASA login (telnet/ssh line) password hash: "passwd <hash> encrypted",
	// plus the LDAP bind and RADIUS common passwords of aaa-server blocks
	{
		re:   regexp.MustCompile(`(?i)(?m)(^\s*(?:passwd|ldap-login-password|radius-common-pw))\s+\S+`),
		repl: "${1} <REDACTED>",
	},
}

// Config processes raw configuration text and replaces recognized sensitive
// credentials, hashes, and community strings with redacted placeholders.
func Config(content string) string {
	result := content
	for _, rule := range commonPatterns {
		result = rule.re.ReplaceAllString(result, rule.repl)
	}
	return result
}
