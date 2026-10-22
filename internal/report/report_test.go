package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFormatFileSize(t *testing.T) {
	tests := []struct {
		bytes   int64
		want    string
		wantErr bool
	}{
		{-1, "-", false},
		{-2, "", true},
		{0, "0 B", false},
		{1023, "1023 B", false},
		{1024, "1.00 KiB", false},
		{45896, "44.82 KiB", false},
		{1024 * 1024, "1.00 MiB", false},
	}

	for _, tt := range tests {
		got, err := FormatFileSize(tt.bytes)
		if tt.wantErr {
			if err == nil {
				t.Errorf("FormatFileSize(%d): expected error, got nil", tt.bytes)
			}
			continue
		}
		if err != nil {
			t.Errorf("FormatFileSize(%d): unexpected error: %v", tt.bytes, err)
			continue
		}
		if got != tt.want {
			t.Errorf("FormatFileSize(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		seconds float64
		want    string
		wantErr bool
	}{
		{-0.5, "", true},
		{0, "0.00s", false},
		{3.42, "3.42s", false},
		{65.5, "1m05.5s", false},
	}

	for _, tt := range tests {
		got, err := FormatDuration(tt.seconds)
		if tt.wantErr {
			if err == nil {
				t.Errorf("FormatDuration(%v): expected error, got nil", tt.seconds)
			}
			continue
		}
		if err != nil {
			t.Errorf("FormatDuration(%v): unexpected error: %v", tt.seconds, err)
			continue
		}
		if got != tt.want {
			t.Errorf("FormatDuration(%v) = %q, want %q", tt.seconds, got, tt.want)
		}
	}
}

func TestColorForStatus(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{StatusSuccess, ansiGreen},
		{StatusDryRun, ansiGreen},
		{StatusUnchanged, ansiGreen},
		{StatusAuthFailed, ansiRed},
		{StatusTimeout, ansiYellow},
		{StatusFailed, ansiRed},
		{"auth failed", ansiRed}, // case-insensitive
		{"something odd", ""},    // unrecognized -> no color, not an alarming default
	}

	for _, tt := range tests {
		if got := colorForStatus(tt.status); got != tt.want {
			t.Errorf("colorForStatus(%q) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

// TestBuildRowNeverPanicsOnBadInput exercises the defense described in the
// package doc: a BackupResult with values that can never be valid must
// degrade to a placeholder cell plus a warning, not panic.
func TestBuildRowNeverPanicsOnBadInput(t *testing.T) {
	bad := BackupResult{
		HostnameIP: "bogus-host",
		FileSize:   -99,   // invalid: only -1 is a valid sentinel
		Duration:   -12.3, // invalid: negative duration
		Error:      errors.New("boom"),
	}

	row, warnings := buildRow(bad)

	if len(warnings) != 2 {
		t.Fatalf("expected 2 warnings (file size + duration), got %d: %v", len(warnings), warnings)
	}
	if row.cells[3] != "N/A" {
		t.Errorf("FileSize cell = %q, want N/A", row.cells[3])
	}
	if row.cells[4] != "N/A" {
		t.Errorf("Duration cell = %q, want N/A", row.cells[4])
	}
}

// TestPrintSummaryTableNeverPanics backs the package's core guarantee:
// no input to the table renderer -- empty, nil, or malformed -- should
// ever crash the caller's goroutine.
func TestPrintSummaryTableNeverPanics(t *testing.T) {
	inputs := [][]BackupResult{
		nil,
		{},
		MockResults(),
		{{HostnameIP: "", Platform: "", Status: "", FileSize: -5, Duration: -1, Error: nil}},
	}

	for _, results := range inputs {
		var out, warn bytes.Buffer
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("fprintSummaryTable panicked: %v", r)
				}
			}()
			fprintSummaryTable(&out, &warn, results, false)
		}()

		if out.Len() == 0 {
			t.Error("expected non-empty table output even for degenerate input")
		}
	}
}

// TestPlainOutputHasNoEscapeCodes checks that colorize=false (the
// non-terminal / NO_COLOR path) really does yield plain, diff-friendly
// text with no ANSI codes.
func TestPlainOutputHasNoEscapeCodes(t *testing.T) {
	var out, warn bytes.Buffer
	fprintSummaryTable(&out, &warn, MockResults(), false)

	if strings.Contains(out.String(), "\033[") {
		t.Error("expected no ANSI escape codes when colorize=false")
	}
	for _, want := range []string{"HOSTNAME/IP", "SUCCESS", "AUTH FAILED", "TIMEOUT"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("expected output to contain %q", want)
		}
	}
}

// TestColorOnlyAppliedToStatusColumn confirms coloring is scoped to the
// STATUS cell and only emitted when colorize=true.
func TestColorOnlyAppliedToStatusColumn(t *testing.T) {
	var out, warn bytes.Buffer
	fprintSummaryTable(&out, &warn, MockResults(), true)

	if !strings.Contains(out.String(), ansiGreen) {
		t.Error("expected green ANSI code for a SUCCESS row when colorize=true")
	}
	if !strings.Contains(out.String(), ansiRed) {
		t.Error("expected red ANSI code for an AUTH FAILED row when colorize=true")
	}
}

func TestTableWithDiffColumn(t *testing.T) {
	results := []BackupResult{
		{
			HostnameIP: "sw1 (10.0.0.1)",
			Platform:   "vyos",
			Status:     StatusSuccess,
			FileSize:   1234,
			Duration:   1.5,
			Diff:       "+2/-1",
		},
		{
			HostnameIP: "sw2 (10.0.0.2)",
			Platform:   "vyos",
			Status:     StatusUnchanged,
			FileSize:   -1,
			Duration:   1.0,
			Diff:       "-",
		},
	}

	var out, warn bytes.Buffer
	fprintSummaryTable(&out, &warn, results, false)

	tableStr := out.String()
	if !strings.Contains(tableStr, "DIFF") {
		t.Errorf("expected table to contain DIFF column header, got:\n%s", tableStr)
	}
	if !strings.Contains(tableStr, "+2/-1") {
		t.Errorf("expected table to contain '+2/-1', got:\n%s", tableStr)
	}
}

func TestTableWithTotalRuntime(t *testing.T) {
	results := []BackupResult{
		{
			HostnameIP: "sw1 (10.0.0.1)",
			Platform:   "vyos",
			Status:     StatusSuccess,
			FileSize:   1234,
			Duration:   1.5,
		},
		{
			HostnameIP: "sw2 (10.0.0.2)",
			Platform:   "vyos",
			Status:     StatusSuccess,
			FileSize:   1234,
			Duration:   1.0,
		},
	}

	// Case 1: computed from sum of device durations
	var out1, warn1 bytes.Buffer
	fprintSummaryTable(&out1, &warn1, results, false)
	if !strings.Contains(out1.String(), "Total Runtime: 2.50s") {
		t.Errorf("expected Total Runtime: 2.50s, got:\n%s", out1.String())
	}

	// Case 2: explicit wall-clock total runtime
	var out2, warn2 bytes.Buffer
	fprintSummaryTable(&out2, &warn2, results, false, 5*time.Second)
	if !strings.Contains(out2.String(), "Total Runtime: 5.00s") {
		t.Errorf("expected Total Runtime: 5.00s, got:\n%s", out2.String())
	}
}

func TestFormatError(t *testing.T) {
	if got := formatError(nil); got != "-" {
		t.Errorf("formatError(nil) = %q, want %q", got, "-")
	}

	shortErr := errors.New("connection reset by peer")
	if got := formatError(shortErr); got != "connection reset by peer" {
		t.Errorf("formatError(shortErr) = %q, want %q", got, "connection reset by peer")
	}

	// Newlines replaced with spaces
	multiline := errors.New("line 1\nline 2")
	if got := formatError(multiline); got != "line 1 line 2" {
		t.Errorf("formatError(multiline) = %q, want %q", got, "line 1 line 2")
	}

	// Custom maxWidth
	longErr := errors.New("0123456789abcdef")
	if got := formatError(longErr, 10); got != "012345678…" {
		t.Errorf("formatError(longErr, 10) = %q, want %q", got, "012345678…")
	}

	// Default limit (100)
	longMsg := strings.Repeat("a", 150)
	gotDefault := formatError(errors.New(longMsg))
	if len([]rune(gotDefault)) != defaultMaxErrorColumnWidth {
		t.Errorf("expected default truncation length %d, got %d", defaultMaxErrorColumnWidth, len([]rune(gotDefault)))
	}
	if !strings.HasSuffix(gotDefault, "…") {
		t.Errorf("expected ellipsis suffix, got %q", gotDefault)
	}
}

func TestStatusWithIcon(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{StatusSuccess, "✔ SUCCESS"},
		{StatusDryRun, "✔ SUCCESS (dry-run)"},
		{StatusUnchanged, "✔ UNCHANGED"},
		{StatusTimeout, "⏱ TIMEOUT"},
		{StatusAuthFailed, "✖ AUTH FAILED"},
		{StatusFailed, "✖ FAILED"},
	}
	for _, tt := range tests {
		if got := statusWithIcon(tt.status); got != tt.want {
			t.Errorf("statusWithIcon(%q) = %q, want %q", tt.status, got, tt.want)
		}
	}
}
