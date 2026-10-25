package task

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/internal/inventory"
)

func TestSummaryShowsSafetyColumnOnlyWhenRated(t *testing.T) {
	mk := func(host, rating string) Result {
		return Result{Device: inventory.Device{Hostname: host, Vendor: "cisco"}, Status: StatusSucceeded, SafetyRating: rating}
	}
	out := Summarize([]Result{mk("a", "SAFE"), mk("b", "REBOOT REQUIRED"), mk("c", "UNSAFE / OOB REQUIRED"), mk("d", "")}).Render(RenderOptions{})
	for _, want := range []string{"SAFETY", "SAFE", "REBOOT REQUIRED", "UNSAFE / OOB REQUIRED"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	if out := Summarize([]Result{mk("a", "")}).Render(RenderOptions{}); strings.Contains(out, "SAFETY") {
		t.Fatalf("no device was rated (operational mode): no empty column:\n%s", out)
	}
}

func TestSummaryShowsVerifyFailedBadge(t *testing.T) {
	out := Summarize([]Result{
		{Device: inventory.Device{Hostname: "sw1", Vendor: "junos"}, Status: StatusFailed, Category: CatVerifyFailed, Detail: "VERIFY FAILED: x"},
		{Device: inventory.Device{Hostname: "sw2", Vendor: "junos"}, Status: StatusFailed, Category: CatSyntaxError},
	}).Render(RenderOptions{})
	if !strings.Contains(out, "✖ VERIFY FAILED") {
		t.Fatalf("a failed health check is marked VERIFY FAILED in the status column:\n%s", out)
	}
	if strings.Count(out, "✖ FAILED") != 1 {
		t.Fatalf("other failures keep the plain badge:\n%s", out)
	}
	if !strings.Contains(out, "VERIFY_FAILED") || !strings.Contains(out, "SYNTAX_ERROR") {
		t.Fatalf("failure reasons must be listed:\n%s", out)
	}
	if s := Summarize([]Result{{Status: StatusFailed, Category: CatVerifyFailed}}); s.Failed != 1 {
		t.Fatalf("VERIFY FAILED counts as a failure (non-zero exit): %+v", s)
	}
}

func TestSummarySafetyDroppedBeforeEssentialColumnsOnNarrowTerminals(t *testing.T) {
	r := Result{Device: inventory.Device{Hostname: "sw1", Address: "10.0.0.1", Vendor: "cisco"}, Status: StatusSucceeded,
		SafetyRating: "UNSAFE / OOB REQUIRED", Detail: "ok", Duration: time.Second}
	out := Summarize([]Result{r}).Render(RenderOptions{Width: 60})
	if strings.Contains(out, "SAFETY") {
		t.Fatalf("SAFETY is optional and must give way on a narrow terminal:\n%s", out)
	}
	if !strings.Contains(out, "HOST") || !strings.Contains(out, "STATUS") {
		t.Fatalf("essential columns must survive:\n%s", out)
	}
}

func TestBackupColumnShowsNativeRollbackWithoutBackupFile(t *testing.T) {
	r := Result{Device: inventory.Device{Hostname: "sw1", Vendor: "junos"}, Status: StatusFailed, Rollback: RollbackOK}
	if got := backupCell(r); got != "ROLLED_BACK" {
		t.Fatalf("a native revert must be visible even without -backup, got %q", got)
	}
	if !anyBackupActivity([]Result{r}) {
		t.Fatal("the column must appear")
	}
	if got := backupCell(Result{BackupPath: "/x"}); got != "SAVED" {
		t.Fatalf("unchanged behaviour: %q", got)
	}
	if got := backupCell(Result{}); got != "-" {
		t.Fatalf("unchanged behaviour: %q", got)
	}
}

func TestReportsCarrySafetyAndVerification(t *testing.T) {
	results := []Result{
		{Device: inventory.Device{Hostname: "sw1", Address: "10.0.0.1", Vendor: "junos"}, Status: StatusSucceeded,
			SafetyRating: "SAFE", VerifyPassed: 2, VerifyTotal: 2, CommandsApplied: 1, CommandsTotal: 1},
		{Device: inventory.Device{Hostname: "sw2", Address: "10.0.0.2", Vendor: "cisco"}, Status: StatusFailed, Category: CatVerifyFailed,
			Detail: "VERIFY FAILED: x", SafetyRating: "REBOOT REQUIRED", VerifyPassed: 1, VerifyTotal: 2},
		{Device: inventory.Device{Hostname: "sw3", Vendor: "cisco"}, Status: StatusSkipped, Category: CatNoCredentials},
	}
	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "r.json")
	if err := WriteJSONReport(jsonPath, results, ""); err != nil {
		t.Fatal(err)
	}
	var rep JSONReport
	data, _ := os.ReadFile(jsonPath)
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	d := rep.Devices
	if d[0].RollbackSafety != "SAFE" || d[0].VerifyPassed != 2 || d[0].VerifyTotal != 2 {
		t.Fatalf("sw1: %+v", d[0])
	}
	if d[1].Category != "VERIFY_FAILED" || d[1].RollbackSafety != "REBOOT REQUIRED" || d[1].VerifyPassed != 1 || d[1].VerifyTotal != 2 {
		t.Fatalf("sw2: %+v", d[1])
	}
	if strings.Contains(string(data), `"verify_total": 0`) || strings.Contains(string(data), `"rollback_safety": ""`) {
		t.Fatalf("empty values are omitted so existing consumers see no noise:\n%s", data)
	}

	csvPath := filepath.Join(dir, "r.csv")
	if err := WriteCSVReport(csvPath, results, ""); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(csvPath)
	text := string(data)
	for _, want := range []string{
		// the original columns keep their positions: new ones are appended
		"diff_removed,output_file,rollback_safety,verify_passed,verify_total",
		"sw1,10.0.0.1,junos,SUCCEEDED,,,0,1,1,,,0,0,,SAFE,2,2",
		"VERIFY_FAILED,VERIFY FAILED: x,0,0,0,,,0,0,,REBOOT REQUIRED,1,2",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("CSV lacks %q in:\n%s", want, text)
		}
	}
}
