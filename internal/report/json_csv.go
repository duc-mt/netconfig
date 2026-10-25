// ==============================================================================
// Package report implements machine-readable JSON and CSV audit run reports.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-18
// License:       MIT
// ==============================================================================
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netops/internal/backup"
)

// AuditRecord is a machine-readable summary record of one device backup outcome.
type AuditRecord struct {
	Hostname      string `json:"hostname"`
	IPAddress     string `json:"ip_address"`
	Vendor        string `json:"vendor"`
	Status        string `json:"status"` // SUCCEEDED, FAILED, SKIPPED
	BytesWritten  int64  `json:"bytes_written"`
	DurationMS    int64  `json:"duration_ms"`
	Checksum      string `json:"checksum"` // SHA-256 hex string, or ""
	FailureReason string `json:"failure_reason,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
	OutputPath    string `json:"output_path,omitempty"`
}

// AuditReport is the top-level payload for JSON audit reports.
type AuditReport struct {
	RunName      string        `json:"run_name"`
	GeneratedAt  time.Time     `json:"generated_at"`
	TotalDevices int           `json:"total_devices"`
	Succeeded    int           `json:"succeeded"`
	Failed       int           `json:"failed"`
	Skipped      int           `json:"skipped"`
	DurationMS   int64         `json:"duration_ms"`
	Records      []AuditRecord `json:"records"`
}

// FromBackupResultsToAudit converts backup.Result slice to AuditRecord slice.
func FromBackupResultsToAudit(results []backup.Result) []AuditRecord {
	records := make([]AuditRecord, 0, len(results))
	for _, r := range results {
		var status, failureReason, errMsg string

		if r.Success {
			switch {
			case r.DryRun:
				status = "DRY_RUN"
			case r.Unchanged && r.BytesWritten == 0:
				status = "SKIPPED"
			default:
				status = "SUCCEEDED"
			}
		} else {
			status = "FAILED"
			failureReason = r.Category.AuditReason()
			if r.Err != nil {
				errMsg = r.Err.Error()
			}
		}

		records = append(records, AuditRecord{
			Hostname:      r.Device.Hostname,
			IPAddress:     r.Device.Address,
			Vendor:        r.Device.Vendor,
			Status:        status,
			BytesWritten:  r.BytesWritten,
			DurationMS:    r.Duration.Milliseconds(),
			Checksum:      r.Checksum,
			FailureReason: failureReason,
			ErrorMessage:  errMsg,
			OutputPath:    r.OutputPath,
		})
	}
	return records
}

// FromResultsToAudit converts []BackupResult to []AuditRecord.
func FromResultsToAudit(rows []BackupResult) []AuditRecord {
	records := make([]AuditRecord, 0, len(rows))
	for _, r := range rows {
		var status, failureReason, errMsg string

		switch r.Status {
		case StatusSuccess:
			status = "SUCCEEDED"
		case StatusDryRun:
			status = "DRY_RUN"
		case StatusUnchanged:
			status = "SKIPPED"
		default:
			status = "FAILED"
			switch r.Status {
			case StatusAuthFailed:
				failureReason = "AUTH_FAILED"
			case StatusTimeout:
				failureReason = "TIMEOUT"
			case "TRUNCATED":
				failureReason = "TRUNCATED_OUTPUT"
			default:
				if strings.Contains(strings.ToUpper(r.Status), "CONNECT") || strings.Contains(strings.ToUpper(r.Status), "UNREACH") {
					failureReason = "CONNECT_FAILED"
				} else {
					failureReason = "FAILED"
				}
			}
			if r.Error != nil {
				errMsg = r.Error.Error()
			}
		}

		bytesWritten := r.FileSize
		if bytesWritten < 0 {
			bytesWritten = 0
		}

		host := r.Hostname
		if host == "" {
			host = r.HostnameIP
		}

		records = append(records, AuditRecord{
			Hostname:      host,
			IPAddress:     r.Address,
			Vendor:        r.Platform,
			Status:        status,
			BytesWritten:  bytesWritten,
			DurationMS:    int64(r.Duration * 1000),
			Checksum:      r.Checksum,
			FailureReason: failureReason,
			ErrorMessage:  errMsg,
		})
	}
	return records
}

// WriteJSON writes a machine-readable JSON run report atomically to path.
func WriteJSON(path string, info RunInfo, records []AuditRecord) ([]string, error) {
	succeeded := 0
	failed := 0
	skipped := 0
	var totalDurationMS int64
	for _, rec := range records {
		totalDurationMS += rec.DurationMS
		switch rec.Status {
		case "SUCCEEDED", "DRY_RUN":
			succeeded++
		case "SKIPPED":
			skipped++
		default:
			failed++
		}
	}

	report := AuditReport{
		RunName:      info.RunName,
		GeneratedAt:  info.GeneratedAt,
		TotalDevices: len(records),
		Succeeded:    succeeded,
		Failed:       failed,
		Skipped:      skipped,
		DurationMS:   totalDurationMS,
		Records:      records,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding JSON report: %w", err)
	}

	if err := writeFileAtomic(path, data); err != nil {
		return nil, fmt.Errorf("writing JSON report: %w", err)
	}
	return nil, nil
}

// WriteCSV writes a machine-readable CSV audit summary atomically to path.
func WriteCSV(path string, info RunInfo, records []AuditRecord) ([]string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating CSV report dir: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".netbackup-csv-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp CSV file: %w", err)
	}
	tmpName := tmpFile.Name()
	cleaned := false
	defer func() {
		if !cleaned {
			_ = tmpFile.Close()
			_ = os.Remove(tmpName)
		}
	}()

	w := csv.NewWriter(tmpFile)
	header := []string{
		"hostname",
		"ip_address",
		"vendor",
		"status",
		"bytes_written",
		"duration_ms",
		"checksum",
		"failure_reason",
		"error_message",
		"output_path",
	}
	if err := w.Write(header); err != nil {
		return nil, fmt.Errorf("writing CSV header: %w", err)
	}

	for _, rec := range records {
		row := []string{
			rec.Hostname,
			rec.IPAddress,
			rec.Vendor,
			rec.Status,
			strconv.FormatInt(rec.BytesWritten, 10),
			strconv.FormatInt(rec.DurationMS, 10),
			rec.Checksum,
			rec.FailureReason,
			rec.ErrorMessage,
			rec.OutputPath,
		}
		if err := w.Write(row); err != nil {
			return nil, fmt.Errorf("writing CSV row for %s: %w", rec.Hostname, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("flushing CSV: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		return nil, fmt.Errorf("syncing temp CSV file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("closing temp CSV file: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return nil, fmt.Errorf("renaming temp CSV file: %w", err)
	}
	cleaned = true
	return nil, nil
}
