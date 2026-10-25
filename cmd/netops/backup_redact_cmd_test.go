// ==============================================================================
// File name:     backup_redact_cmd_test.go
// Description:   Tests for the "backup redact" subcommand.
// License:       MIT
// ==============================================================================
package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/internal/task"
)

func runRedactCLI(args ...string) (int, string, string) {
	in, err := os.Open(os.DevNull)
	if err != nil {
		panic(err)
	}
	defer in.Close()
	var out, errb bytes.Buffer
	fullArgs := append([]string{"backup", "redact"}, args...)
	code := dispatch(fullArgs, in, &out, &errb)
	return code, out.String(), errb.String()
}

func TestBackupRedactHelp(t *testing.T) {
	code, _, errOut := runRedactCLI("-h")
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d", code, task.ExitOK)
	}
	if !strings.Contains(errOut, "netops backup redact [flags] <file-or-dir>") {
		t.Errorf("help missing usage banner:\n%s", errOut)
	}
	if !strings.Contains(errOut, "-zip") || !strings.Contains(errOut, "-in-place") {
		t.Errorf("help missing flags:\n%s", errOut)
	}
}

func TestBackupRedactValidationErrors(t *testing.T) {
	// No argument
	code, _, errOut := runRedactCLI()
	if code != task.ExitFatal || !strings.Contains(errOut, "Target file or directory is required") {
		t.Errorf("expected missing target error, got code %d:\n%s", code, errOut)
	}

	// Multiple positional arguments
	code, _, errOut = runRedactCLI("file1.cfg", "file2.cfg")
	if code != task.ExitFatal || !strings.Contains(errOut, "unexpected arguments") {
		t.Errorf("expected unexpected arguments error, got code %d:\n%s", code, errOut)
	}

	// File not found
	code, _, errOut = runRedactCLI("non_existent_file.cfg")
	if code != task.ExitFatal || !strings.Contains(errOut, "no such file") {
		t.Errorf("expected file not found error, got code %d:\n%s", code, errOut)
	}

	// In-place conflicting with -o or -zip
	dir := t.TempDir()
	sampleFile := filepath.Join(dir, "sw.cfg")
	_ = os.WriteFile(sampleFile, []byte("enable secret 5 secret123\n"), 0o600)

	code, _, errOut = runRedactCLI("-i", "-o", "out.cfg", sampleFile)
	if code != task.ExitFatal || !strings.Contains(errOut, "-in-place cannot be combined") {
		t.Errorf("expected conflicting flags error, got code %d:\n%s", code, errOut)
	}

	code, _, errOut = runRedactCLI("-i", "-zip", sampleFile)
	if code != task.ExitFatal || !strings.Contains(errOut, "-in-place cannot be combined") {
		t.Errorf("expected conflicting flags error, got code %d:\n%s", code, errOut)
	}
}

func TestBackupRedactSingleFileToStdout(t *testing.T) {
	dir := t.TempDir()
	sampleFile := filepath.Join(dir, "sw.cfg")
	content := "hostname sw1\nenable secret 5 MySecretHash123\nsnmp-server community secretComm RO\n"
	if err := os.WriteFile(sampleFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runRedactCLI(sampleFile)
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d\nstderr:\n%s", code, task.ExitOK, stderr)
	}

	if strings.Contains(stdout, "MySecretHash123") || strings.Contains(stdout, "secretComm") {
		t.Errorf("secrets leaked in stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "enable secret 5 <REDACTED>") || !strings.Contains(stdout, "snmp-server community <REDACTED> RO") {
		t.Errorf("redacted markers missing in stdout:\n%s", stdout)
	}

	// Source file remains unchanged
	orig, _ := os.ReadFile(sampleFile)
	if string(orig) != content {
		t.Errorf("source file was unexpectedly mutated")
	}
}

func TestBackupRedactSingleFileToOutputFile(t *testing.T) {
	dir := t.TempDir()
	sampleFile := filepath.Join(dir, "sw.cfg")
	outFile := filepath.Join(dir, "sub", "sw-sanitized.cfg")
	content := "hostname sw1\nenable password level 15 encrypted EncryptedPass99\n"
	if err := os.WriteFile(sampleFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runRedactCLI("-o", outFile, "-v", sampleFile)
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d\nstderr:\n%s", code, task.ExitOK, stderr)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	res := string(data)
	if strings.Contains(res, "EncryptedPass99") {
		t.Errorf("secret survived in output:\n%s", res)
	}
	if !strings.Contains(res, "enable password level 15 encrypted <REDACTED>") {
		t.Errorf("redaction marker missing:\n%s", res)
	}
}

func TestBackupRedactSingleFileInPlace(t *testing.T) {
	dir := t.TempDir()
	sampleFile := filepath.Join(dir, "sw.cfg")
	content := "hostname sw1\nusername admin secret 5 HashAdmin123\n"
	if err := os.WriteFile(sampleFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runRedactCLI("-i", "-v", sampleFile)
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d\nstderr:\n%s", code, task.ExitOK, stderr)
	}

	data, err := os.ReadFile(sampleFile)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	res := string(data)
	if strings.Contains(res, "HashAdmin123") {
		t.Errorf("secret survived in file:\n%s", res)
	}
	if !strings.Contains(res, "username admin secret 5 <REDACTED>") {
		t.Errorf("redaction marker missing:\n%s", res)
	}
}

func TestBackupRedactSingleFileToZip(t *testing.T) {
	dir := t.TempDir()
	sampleFile := filepath.Join(dir, "router.conf")
	zipFile := filepath.Join(dir, "export.zip")
	content := "set system root-authentication encrypted-password \"$6$rounds=1000$salt$SecretHash\"\n"
	if err := os.WriteFile(sampleFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runRedactCLI("-o", zipFile, sampleFile)
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d\nstderr:\n%s", code, task.ExitOK, stderr)
	}

	zr, err := zip.OpenReader(zipFile)
	if err != nil {
		t.Fatalf("opening zip: %v", err)
	}
	defer zr.Close()

	if len(zr.File) != 1 || zr.File[0].Name != "router.conf" {
		t.Fatalf("unexpected zip entries: %v", zr.File)
	}

	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	body, _ := io.ReadAll(rc)
	res := string(body)

	if strings.Contains(res, "SecretHash") {
		t.Errorf("secret leaked in zip entry:\n%s", res)
	}
	if !strings.Contains(res, `encrypted-password "<REDACTED>"`) {
		t.Errorf("expected redacted marker in zip:\n%s", res)
	}
}

func TestBackupRedactDirectoryToDirectory(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "backup-run")
	ciscoDir := filepath.Join(srcDir, "cisco_ios")
	juniperDir := filepath.Join(srcDir, "juniper_junos")
	_ = os.MkdirAll(ciscoDir, 0o700)
	_ = os.MkdirAll(juniperDir, 0o700)

	_ = os.WriteFile(filepath.Join(ciscoDir, "sw1.cfg"), []byte("hostname sw1\nenable secret 5 Secret1\n"), 0o600)
	_ = os.WriteFile(filepath.Join(juniperDir, "r1.set"), []byte("set system login user bob authentication encrypted-password \"$6$Secret2\"\n"), 0o600)
	// non-secret file
	_ = os.WriteFile(filepath.Join(srcDir, "summary.txt"), []byte("Backup run summary: 2 devices\n"), 0o600)

	outDir := filepath.Join(dir, "backup-clean")
	code, _, stderr := runRedactCLI("-o", outDir, "-v", srcDir)
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d\nstderr:\n%s", code, task.ExitOK, stderr)
	}

	// Verify cisco sw1
	sw1Data, err := os.ReadFile(filepath.Join(outDir, "cisco_ios", "sw1.cfg"))
	if err != nil {
		t.Fatalf("reading redacted sw1: %v", err)
	}
	if strings.Contains(string(sw1Data), "Secret1") || !strings.Contains(string(sw1Data), "<REDACTED>") {
		t.Errorf("cisco secret not redacted:\n%s", string(sw1Data))
	}

	// Verify juniper r1
	r1Data, err := os.ReadFile(filepath.Join(outDir, "juniper_junos", "r1.set"))
	if err != nil {
		t.Fatalf("reading redacted r1: %v", err)
	}
	if strings.Contains(string(r1Data), "Secret2") || !strings.Contains(string(r1Data), "<REDACTED>") {
		t.Errorf("juniper secret not redacted:\n%s", string(r1Data))
	}

	// Verify summary.txt preserved
	sumData, err := os.ReadFile(filepath.Join(outDir, "summary.txt"))
	if err != nil || !strings.Contains(string(sumData), "Backup run summary") {
		t.Errorf("summary file missing or corrupted: %v", err)
	}
}

func TestBackupRedactDirectoryDefaultDestination(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "mybackup")
	_ = os.MkdirAll(srcDir, 0o700)
	_ = os.WriteFile(filepath.Join(srcDir, "dev.cfg"), []byte("password 0 PlainTextPassword\n"), 0o600)

	code, _, stderr := runRedactCLI(srcDir)
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d\nstderr:\n%s", code, task.ExitOK, stderr)
	}

	expectedDir := filepath.Join(dir, "mybackup-redacted")
	data, err := os.ReadFile(filepath.Join(expectedDir, "dev.cfg"))
	if err != nil {
		t.Fatalf("reading default output dir file: %v", err)
	}
	if strings.Contains(string(data), "PlainTextPassword") || !strings.Contains(string(data), "<REDACTED>") {
		t.Errorf("secret not redacted in default dir:\n%s", string(data))
	}
}

func TestBackupRedactDirectoryToZip(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "backup-run")
	subDir := filepath.Join(srcDir, "cisco")
	_ = os.MkdirAll(subDir, 0o700)
	_ = os.WriteFile(filepath.Join(subDir, "core.cfg"), []byte("radius-server key TopSecretRadius\n"), 0o600)

	zipDest := filepath.Join(dir, "backup-export.zip")
	code, _, stderr := runRedactCLI("-o", zipDest, "-v", srcDir)
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d\nstderr:\n%s", code, task.ExitOK, stderr)
	}

	zr, err := zip.OpenReader(zipDest)
	if err != nil {
		t.Fatalf("reading zip: %v", err)
	}
	defer zr.Close()

	found := false
	for _, f := range zr.File {
		if filepath.ToSlash(f.Name) == "cisco/core.cfg" {
			found = true
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(rc)
			rc.Close()
			if strings.Contains(string(data), "TopSecretRadius") {
				t.Errorf("secret leaked in zip:\n%s", string(data))
			}
			if !strings.Contains(string(data), "<REDACTED>") {
				t.Errorf("redaction marker missing in zip:\n%s", string(data))
			}
		}
	}
	if !found {
		t.Errorf("expected entry cisco/core.cfg missing from zip")
	}
}

func TestBackupRedactDirectoryInPlace(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "run")
	_ = os.MkdirAll(srcDir, 0o700)
	devFile := filepath.Join(srcDir, "sw.cfg")
	_ = os.WriteFile(devFile, []byte("snmp-server community MySecretStr RW\n"), 0o600)

	code, _, stderr := runRedactCLI("-i", "-v", srcDir)
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d\nstderr:\n%s", code, task.ExitOK, stderr)
	}

	data, err := os.ReadFile(devFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "MySecretStr") {
		t.Errorf("secret survived in-place redaction:\n%s", string(data))
	}
	if !strings.Contains(string(data), "snmp-server community <REDACTED> RW") {
		t.Errorf("redaction marker missing:\n%s", string(data))
	}
}
