package report

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netconfig/internal/backup"
	"netconfig/internal/errcat"
	"netconfig/internal/inventory"
)

func TestJSONAndCSVReports(t *testing.T) {
	tempDir := t.TempDir()
	jsonPath := filepath.Join(tempDir, "run_report.json")
	csvPath := filepath.Join(tempDir, "run_report.csv")

	results := []backup.Result{
		{
			Device:       inventory.Device{Hostname: "core-sw01", Address: "10.0.0.1", Vendor: "cisco_ios"},
			Success:      true,
			Unchanged:    false,
			OutputPath:   "/tmp/core-sw01.cfg",
			BytesWritten: 4500,
			Checksum:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Duration:     1250 * time.Millisecond,
		},
		{
			Device:       inventory.Device{Hostname: "dist-sw01", Address: "10.0.0.2", Vendor: "aruba"},
			Success:      true,
			Unchanged:    true,
			OutputPath:   "/tmp/dist-sw01.cfg",
			BytesWritten: 0,
			Checksum:     "d41d8cd98f00b204e9800998ecf8427e",
			Duration:     800 * time.Millisecond,
		},
		{
			Device:   inventory.Device{Hostname: "fw-01", Address: "10.0.0.3", Vendor: "fortigate"},
			Success:  false,
			Category: errcat.CategoryAuthFailed,
			Err:      errors.New("authentication failed"),
			Duration: 500 * time.Millisecond,
		},
		{
			Device:   inventory.Device{Hostname: "edge-01", Address: "10.0.0.4", Vendor: "juniper_junos"},
			Success:  false,
			Category: errcat.CategoryTruncatedOutput,
			Err:      errors.New("backup appears truncated or incomplete"),
			Duration: 2100 * time.Millisecond,
		},
	}

	records := FromBackupResultsToAudit(results)
	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}

	if records[0].Status != "SUCCEEDED" || records[0].BytesWritten != 4500 {
		t.Errorf("record 0: unexpected status/bytes: %+v", records[0])
	}
	if records[1].Status != "SKIPPED" {
		t.Errorf("record 1: expected SKIPPED, got %s", records[1].Status)
	}
	if records[2].Status != "FAILED" || records[2].FailureReason != "AUTH_FAILED" {
		t.Errorf("record 2: expected FAILED / AUTH_FAILED, got %+v", records[2])
	}
	if records[3].Status != "FAILED" || records[3].FailureReason != "TRUNCATED_OUTPUT" {
		t.Errorf("record 3: expected FAILED / TRUNCATED_OUTPUT, got %+v", records[3])
	}

	info := RunInfo{RunName: "backup-2026-10-18", GeneratedAt: time.Now()}
	_, err := WriteJSON(jsonPath, info, records)
	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("reading JSON: %v", err)
	}
	var auditRep AuditReport
	if err := json.Unmarshal(jsonData, &auditRep); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}
	if auditRep.TotalDevices != 4 || auditRep.Succeeded != 1 || auditRep.Skipped != 1 || auditRep.Failed != 2 {
		t.Errorf("unexpected counts in JSON report: %+v", auditRep)
	}

	_, err = WriteCSV(csvPath, info, records)
	if err != nil {
		t.Fatalf("WriteCSV failed: %v", err)
	}

	csvFile, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("opening CSV: %v", err)
	}
	defer csvFile.Close()

	reader := csv.NewReader(csvFile)
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("reading CSV: %v", err)
	}
	if len(rows) != 5 { // 1 header + 4 records
		t.Fatalf("expected 5 CSV rows, got %d", len(rows))
	}
	if rows[0][0] != "hostname" || rows[0][7] != "failure_reason" {
		t.Errorf("unexpected CSV header: %v", rows[0])
	}
	if rows[3][3] != "FAILED" || rows[3][7] != "AUTH_FAILED" {
		t.Errorf("unexpected CSV row 3: %v", rows[3])
	}
	if rows[4][3] != "FAILED" || rows[4][7] != "TRUNCATED_OUTPUT" {
		t.Errorf("unexpected CSV row 4: %v", rows[4])
	}
}

func TestAuditReportDryRun(t *testing.T) {
	tempDir := t.TempDir()
	jsonPath := filepath.Join(tempDir, "dry_run.json")
	csvPath := filepath.Join(tempDir, "dry_run.csv")

	results := []backup.Result{
		{
			Device:   inventory.Device{Hostname: "core-sw01", Address: "10.0.0.1", Vendor: "cisco_ios"},
			Success:  true,
			DryRun:   true,
			Duration: 120 * time.Millisecond,
		},
		{
			Device:   inventory.Device{Hostname: "edge-sw01", Address: "10.0.0.2", Vendor: "arista_eos"},
			Success:  false,
			Category: errcat.CategoryAuthFailed,
			Err:      errors.New("bad password"),
			Duration: 80 * time.Millisecond,
		},
	}

	records := FromBackupResultsToAudit(results)
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].Status != "DRY_RUN" {
		t.Errorf("record 0: expected status DRY_RUN, got %s", records[0].Status)
	}
	if records[0].BytesWritten != 0 {
		t.Errorf("record 0: expected BytesWritten 0, got %d", records[0].BytesWritten)
	}

	info := RunInfo{RunName: "backup-dryrun", GeneratedAt: time.Now()}
	_, err := WriteJSON(jsonPath, info, records)
	if err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("reading JSON: %v", err)
	}
	var auditRep AuditReport
	if err := json.Unmarshal(jsonData, &auditRep); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}
	if auditRep.TotalDevices != 2 || auditRep.Succeeded != 1 || auditRep.Failed != 1 {
		t.Errorf("unexpected counts in JSON report: %+v", auditRep)
	}

	_, err = WriteCSV(csvPath, info, records)
	if err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	csvData, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatalf("reading CSV: %v", err)
	}
	if !strings.Contains(string(csvData), "DRY_RUN") {
		t.Errorf("expected CSV to contain DRY_RUN: %s", string(csvData))
	}
}
