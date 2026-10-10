// ==============================================================================
// Package main implements Implementation and logic for inventory_test..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run inventory_test.go [options]
// Notes:         Go package implementation
// ==============================================================================
package inventory

import (
	"strings"
	"testing"
)

const sample = `# fleet
hostname,address,port,vendor,credential_group
sw1, 10.0.0.1, 22, Cisco, dc1
sw2,10.0.0.2,,junos,
rtr3,2001:db8::1,830,Huawei,dc2
`

func TestParseValid(t *testing.T) {
	devs, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(devs) != 3 {
		t.Fatalf("got %d devices, want 3", len(devs))
	}

	if d := devs[0]; d.Hostname != "sw1" || d.Address != "10.0.0.1" || d.Port != 22 || d.Vendor != "cisco" || d.Group != "dc1" || d.Line != 3 {
		t.Errorf("sw1 parsed wrong: %+v", d)
	}
	if d := devs[1]; d.Port != DefaultPort || d.Group != DefaultGroup || d.Vendor != "junos" {
		t.Errorf("sw2 defaults not applied: %+v", d)
	}
	if d := devs[2]; d.Port != 830 || d.Endpoint() != "[2001:db8::1]:830" {
		t.Errorf("rtr3 parsed wrong: %+v endpoint=%s", d, d.Endpoint())
	}
}

func TestParseWithoutHeader(t *testing.T) {
	devs, err := Parse(strings.NewReader("sw1,10.0.0.1,22,cisco\n"))
	if err != nil || len(devs) != 1 || devs[0].Hostname != "sw1" {
		t.Fatalf("devs=%+v err=%v", devs, err)
	}
}

func TestParseReportsAllRowErrors(t *testing.T) {
	bad := strings.Join([]string{
		"a,10.0.0.1,99999,cisco",
		"b,10.0.0.2,22",
		",10.0.0.3,22,cisco",
		"c,10.0.0.4,22,",
		"d,10.0.0.5,22,cisco",
		"D,10.0.0.6,22,cisco",
		"e,10.0.0.7,abc,cisco",
	}, "\n") + "\n"

	_, err := Parse(strings.NewReader(bad))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		"line 1: invalid port",
		"line 2: expected 4 or 5 fields",
		"line 3: hostname is empty",
		"line 4: vendor is empty",
		"line 6: duplicate hostname",
		"line 7: invalid port",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%v", want, err)
		}
	}
}

func TestParseEmpty(t *testing.T) {
	if _, err := Parse(strings.NewReader("# only a comment\n")); err == nil {
		t.Fatal("expected error for inventory without devices")
	}
}

func TestFilter(t *testing.T) {
	devs, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}

	got, err := Filter(devs, []string{"SW*"})
	if err != nil || len(got) != 2 {
		t.Fatalf("glob: got %d, err=%v", len(got), err)
	}
	got, err = Filter(devs, []string{"@dc2"})
	if err != nil || len(got) != 1 || got[0].Hostname != "rtr3" {
		t.Fatalf("group: got %+v, err=%v", got, err)
	}
	got, err = Filter(devs, nil)
	if err != nil || len(got) != 3 {
		t.Fatalf("no patterns: got %d, err=%v", len(got), err)
	}
	if _, err = Filter(devs, []string{"nomatch*"}); err == nil {
		t.Fatal("expected error for pattern that matches nothing")
	}
}
