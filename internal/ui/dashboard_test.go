package ui

import (
	"bytes"
	"strings"
	"testing"

	"netconfig/internal/inventory"
	"netconfig/internal/task"
	"netconfig/internal/vendor"
)

func TestDashboardLifecycle(t *testing.T) {
	var buf bytes.Buffer
	d := New(Config{
		Writer:       &buf,
		TotalDevices: 10,
		Width:        80,
		Enabled:      true,
	})

	dev1 := inventory.Device{Hostname: "router1", Vendor: "cisco"}
	dev2 := inventory.Device{Hostname: "switch1", Vendor: "junos"}

	d.OnBatchStart(1, 2, 5, false)
	d.OnDeviceStart(dev1)
	d.OnDeviceStep(dev1, vendor.StepBody, "interface GigabitEthernet0/1")
	d.OnDeviceStart(dev2)
	d.OnDeviceStep(dev2, vendor.StepPersist, "commit")

	d.OnDeviceDone(task.Result{
		Device: dev1,
		Status: task.StatusSucceeded,
	})
	d.OnDeviceDone(task.Result{
		Device: dev2,
		Status: task.StatusFailed,
	})

	d.Stop()

	out := buf.String()
	if !strings.Contains(out, "netconfig") {
		t.Errorf("output should contain 'netconfig', got: %q", out)
	}
	if !strings.Contains(out, "router1") {
		t.Errorf("output should contain 'router1', got: %q", out)
	}
}

func TestDashboardDisabled(t *testing.T) {
	var buf bytes.Buffer
	d := New(Config{
		Writer:       &buf,
		TotalDevices: 10,
		Width:        80,
		Enabled:      false,
	})

	dev := inventory.Device{Hostname: "router1", Vendor: "cisco"}
	d.OnDeviceStart(dev)
	d.OnDeviceDone(task.Result{Device: dev, Status: task.StatusSucceeded})
	d.Stop()

	if buf.Len() != 0 {
		t.Errorf("disabled dashboard should not write to output, got: %q", buf.String())
	}
}

func TestRenderBar(t *testing.T) {
	cases := []struct {
		percent int
		width   int
		want    string
	}{
		{0, 10, "[>---------]"},
		{50, 10, "[=====>----]"},
		{100, 10, "[==========]"},
	}
	for _, tc := range cases {
		got := renderBar(tc.percent, tc.width)
		if got != tc.want {
			t.Errorf("renderBar(%d, %d) = %q, want %q", tc.percent, tc.width, got, tc.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	s := "Hello World"
	if got := truncate(s, 8); got != "Hello..." {
		t.Errorf("truncate(%q, 8) = %q, want 'Hello...'", s, got)
	}
	if got := truncate(s, 20); got != s {
		t.Errorf("truncate(%q, 20) = %q, want %q", s, got, s)
	}

	ansiStr := "\x1b[32mHello World\x1b[0m"
	if got := truncate(ansiStr, 8); !strings.HasPrefix(got, "\x1b[32mHello...") {
		t.Errorf("truncate with ANSI = %q", got)
	}
}

func TestDashboardLog(t *testing.T) {
	var buf bytes.Buffer
	d := New(Config{
		Writer:       &buf,
		TotalDevices: 2,
		Width:        80,
		Enabled:      true,
	})
	defer d.Stop()

	d.Log("test message from runner")
	if !strings.Contains(buf.String(), "test message from runner") {
		t.Errorf("expected log message in output, got: %q", buf.String())
	}
}
