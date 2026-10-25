// ==============================================================================
// Package backup implements tests for terminal banner sanitization.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-25
// License:       MIT
// ==============================================================================
package backup

import (
	"strings"
	"testing"
)

func TestCleanTerminalBanners(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name: "ruijie backup banner",
			input: strings.Join([]string{
				"Building configuration...",
				"Current configuration: 7675 bytes",
				"",
				"version CS83_RGOS 12.6(3)B0703, Release(12161105)",
				"hostname DCTTN_TTN_NET_Pro_5F-SW.02-CAM_189.88_U44",
				"!",
				"errdisable recovery interval 60",
			}, "\n"),
			want: strings.Join([]string{
				"version CS83_RGOS 12.6(3)B0703, Release(12161105)",
				"hostname DCTTN_TTN_NET_Pro_5F-SW.02-CAM_189.88_U44",
				"!",
				"errdisable recovery interval 60",
			}, "\n"),
		},
		{
			name: "cisco ios banner with space before colon and blank line",
			input: strings.Join([]string{
				"Building configuration...",
				"",
				"Current configuration : 5123 bytes",
				"!",
				"version 15.2",
				"hostname core-sw01",
				"end",
			}, "\n"),
			want: strings.Join([]string{
				"!",
				"version 15.2",
				"hostname core-sw01",
				"end",
			}, "\n"),
		},
		{
			name: "crlf line endings preserved in remainder",
			input: "Building configuration...\r\n" +
				"Current configuration: 7675 bytes\r\n\r\n" +
				"version CS83_RGOS 12.6\r\n" +
				"hostname sw1\r\n",
			want: "version CS83_RGOS 12.6\r\n" +
				"hostname sw1\r\n",
		},
		{
			name: "leading blank lines before banner",
			input: "\n\n" +
				"Building configuration...\n" +
				"Current configuration: 1234 bytes\n" +
				"hostname sw1\n",
			want: "hostname sw1\n",
		},
		{
			name: "banner only content",
			input: "Building configuration...\n" +
				"Current configuration: 100 bytes\n",
			want: "",
		},
		{
			name: "cisco asa preserved untouched",
			input: strings.Join([]string{
				": Saved",
				":",
				"ASA Version 9.16(4)",
				"hostname asa1",
			}, "\n"),
			want: strings.Join([]string{
				": Saved",
				":",
				"ASA Version 9.16(4)",
				"hostname asa1",
			}, "\n"),
		},
		{
			name: "cisco sb header preserved untouched",
			input: strings.Join([]string{
				"config-file-header",
				"switch1a2b3c",
				"CLI v1.0",
				"@",
				"!",
				"vlan database",
			}, "\n"),
			want: strings.Join([]string{
				"config-file-header",
				"switch1a2b3c",
				"CLI v1.0",
				"@",
				"!",
				"vlan database",
			}, "\n"),
		},
		{
			name: "junos preserved untouched",
			input: strings.Join([]string{
				"set system host-name core-mx1",
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			}, "\n"),
			want: strings.Join([]string{
				"set system host-name core-mx1",
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			}, "\n"),
		},
		{
			name: "description containing banner keywords in body preserved untouched",
			input: strings.Join([]string{
				"hostname core-sw01",
				"interface GigabitEthernet0/1",
				" description Building configuration server link",
				"!",
				"interface GigabitEthernet0/2",
				" description Current configuration: 7675 bytes test",
				"end",
			}, "\n"),
			want: strings.Join([]string{
				"hostname core-sw01",
				"interface GigabitEthernet0/1",
				" description Building configuration server link",
				"!",
				"interface GigabitEthernet0/2",
				" description Current configuration: 7675 bytes test",
				"end",
			}, "\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CleanTerminalBanners(tt.input)
			if got != tt.want {
				t.Errorf("CleanTerminalBanners() mismatch:\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeCheckPointConfig(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "whitespace only",
			input: "   \n\t  \n",
			want:  "   \n\t  \n",
		},
		{
			name: "prepends clienv on-failure continue",
			input: strings.Join([]string{
				"# Configure a persistent Domain Name for the device",
				`set dynamic-dns provider "DynDns"`,
				`set hostname "gw1"`,
			}, "\n"),
			want: strings.Join([]string{
				"# Enable continue on failure so harmless conflicts or duplicate objects do not halt restore",
				"set clienv on-failure continue",
				"# Configure a persistent Domain Name for the device",
				`set dynamic-dns provider "DynDns"`,
				`set hostname "gw1"`,
			}, "\n"),
		},
		{
			name: "does not duplicate clienv on-failure continue if already present",
			input: strings.Join([]string{
				"set clienv on-failure continue",
				`set hostname "gw1"`,
			}, "\n"),
			want: strings.Join([]string{
				"set clienv on-failure continue",
				`set hostname "gw1"`,
			}, "\n"),
		},
		{
			name: "flattens multiline user-check zero-phishing command",
			input: strings.Join([]string{
				`set threat-prevention zero-phishing user-check ask-subject "Are you sure?" ask-body "Your computer is trying to access a malicious server. It is likely infected by malware.`,
				"",
				"Click $mis_categorization_link to report an incorrect classification.",
				"",
				"Malware activity: $activity.",
				"URL: $original_url.",
				"Reference: $incident_id",
				`Press OK to continue." ask-activity-text "Ignore warning" ask-fall-back-action "block" ask-frequency "day" ask-reason-displayed "false" block-title "Check Point Zero Phishing" block-subject "Beware! Deceptive site blocked" block-redirects-to-url "false" block-body "The requested site is a phishing site that may <B>pretend</B> to be legitimate. Phishing sites try to trick you and <B>steal your information</B>`,
				"",
				"(for example, passwords or credit cards).",
				"",
				"For more information, please contact your help desk.Click $mis_categorization_link to report incorrect classification",
				"URL: $original_url",
				`Reference: $incident_id"`,
			}, "\n"),
			want: strings.Join([]string{
				"# Enable continue on failure so harmless conflicts or duplicate objects do not halt restore",
				"set clienv on-failure continue",
				`set threat-prevention zero-phishing user-check ask-subject "Are you sure?" ask-body "Your computer is trying to access a malicious server. It is likely infected by malware. Click $mis_categorization_link to report an incorrect classification. Malware activity: $activity. URL: $original_url. Reference: $incident_id Press OK to continue." ask-activity-text "Ignore warning" ask-fall-back-action "block" ask-frequency "day" ask-reason-displayed "false" block-title "Check Point Zero Phishing" block-subject "Beware! Deceptive site blocked" block-redirects-to-url "false" block-body "The requested site is a phishing site that may <B>pretend</B> to be legitimate. Phishing sites try to trick you and <B>steal your information</B> (for example, passwords or credit cards). For more information, please contact your help desk.Click $mis_categorization_link to report incorrect classification URL: $original_url Reference: $incident_id"`,
			}, "\n"),
		},
		{
			name: "flattens banner with trailing newline before closing quote",
			input: strings.Join([]string{
				`set message type "banner" "on" msgvalue "*** UNAUTHORIZED ACCESS IS PROHIBITED ***`,
				`"`,
			}, "\n"),
			want: strings.Join([]string{
				"# Enable continue on failure so harmless conflicts or duplicate objects do not halt restore",
				"set clienv on-failure continue",
				`set message type "banner" "on" msgvalue "*** UNAUTHORIZED ACCESS IS PROHIBITED ***"`,
			}, "\n"),
		},
		{
			name: "crlf line endings preserved",
			input: "set clienv on-failure continue\r\n" +
				"set hostname \"gw1\"\r\n",
			want: "set clienv on-failure continue\r\n" +
				"set hostname \"gw1\"\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeCheckPointConfig(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeCheckPointConfig() mismatch:\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}
