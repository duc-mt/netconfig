// ==============================================================================
// File name:     backup_redact_cmd.go
// Description:   The "backup redact" subcommand: sanitize sensitive data in saved
//
//	backup files or directories.
//
// License:       MIT
// ==============================================================================
package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"netops/internal/backup"
	"netops/internal/redact"
	"netops/internal/task"
)

const backupRedactUsageText = `Usage:
  netops backup redact [flags] <file-or-dir>

Mask passwords, pre-shared keys, hashes, and SNMP communities in an existing
backup file or directory.

Output options:
  - If <file-or-dir> is a single file and no -o is given, prints to stdout.
  - If -o specifies a .zip file (or -zip is used), output is packed as a zip archive.
  - If <file-or-dir> is a directory and no -o is given, creates <dir>-redacted.
  - If -i is used, files are overwritten in-place with redacted content.

Flags:
  -o, -output <path>    output destination (file, directory, or .zip archive)
  -zip                  package output as a .zip archive
  -i, -in-place         overwrite files in-place with redacted content
  -v, -verbose          log detailed progress

Examples:
  netops backup redact backups/latest/cisco_ios/sw1.cfg
  netops backup redact -o sw1.clean.cfg backups/latest/cisco_ios/sw1.cfg
  netops backup redact -o export.zip backups/latest/cisco_ios/sw1.cfg
  netops backup redact backups/backup-2026-10-25-1600
  netops backup redact -o sanitized/ backups/backup-2026-10-25-1600
  netops backup redact -o backup-export.zip backups/backup-2026-10-25-1600
  netops backup redact -i backups/staging/sw1.cfg
`

// backupRedactFlagGroups is the help layout for "backup redact".
var backupRedactFlagGroups = []flagGroup{{"Flags", []string{"o", "zip", "i", "v"}}}

func isBinaryContent(data []byte) bool {
	return bytes.IndexByte(data, 0) != -1
}

// runBackupRedact is "netops backup redact".
func runBackupRedact(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var (
		output    string
		zipOutput bool
		inPlace   bool
		verbose   bool
	)
	fs := flag.NewFlagSet("netops backup redact", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, backupRedactUsageText)
		printFlagGroups(stderr, fs, backupRedactFlagGroups)
	}

	fs.StringVar(&output, "o", "", "output file, directory, or .zip archive")
	fs.StringVar(&output, "out", "", "alias for -o")
	fs.StringVar(&output, "output", "", "alias for -o")
	fs.BoolVar(&zipOutput, "zip", false, "package output as a .zip archive")
	fs.BoolVar(&inPlace, "i", false, "overwrite files in-place with redacted content")
	fs.BoolVar(&inPlace, "in-place", false, "alias for -i")
	fs.BoolVar(&verbose, "v", false, "print verbose progress")
	fs.BoolVar(&verbose, "verbose", false, "alias for -v")

	// Parse flags and extract positional path
	var positional []string
	for rest := args; ; {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return task.ExitOK
			}
			return task.ExitFatal
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, format+"\n", a...)
		return task.ExitFatal
	}

	if len(positional) == 0 {
		fmt.Fprintln(stderr, "Error: Target file or directory is required.")
		fmt.Fprintln(stderr)
		fs.Usage()
		return task.ExitFatal
	}
	if len(positional) > 1 {
		return fail("netops backup redact: unexpected arguments: %s", strings.Join(positional[1:], " "))
	}

	target := positional[0]
	info, err := os.Stat(target)
	if err != nil {
		return fail("netops backup redact: %v", err)
	}

	if inPlace && (output != "" || zipOutput) {
		return fail("netops backup redact: -in-place cannot be combined with -o or -zip")
	}

	if !info.IsDir() {
		return redactSingleFile(target, info, output, zipOutput, inPlace, verbose, stdout, stderr, fail)
	}
	return redactDirectory(target, output, zipOutput, inPlace, verbose, stdout, stderr, fail)
}

func redactSingleFile(target string, info os.FileInfo, output string, zipOutput, inPlace, verbose bool, stdout, stderr io.Writer, fail func(string, ...any) int) int {
	data, err := os.ReadFile(target)
	if err != nil {
		return fail("netops backup redact: reading %s: %v", target, err)
	}

	redactedData := data
	if !isBinaryContent(data) {
		redactedData = []byte(redact.Config(string(data)))
	}

	if inPlace {
		if err := backup.WriteFileAtomic(target, redactedData, info.Mode().Perm()); err != nil {
			return fail("netops backup redact: writing %s: %v", target, err)
		}
		if verbose {
			fmt.Fprintf(stderr, "Redacted %s in-place\n", target)
		}
		return task.ExitOK
	}

	isZip := zipOutput || strings.HasSuffix(strings.ToLower(output), ".zip")
	if isZip {
		zipPath := output
		if zipPath == "" {
			base := strings.TrimSuffix(filepath.Base(target), filepath.Ext(target))
			zipPath = base + "-redacted.zip"
		} else if strings.HasSuffix(zipPath, "/") || strings.HasSuffix(zipPath, "\\") {
			base := strings.TrimSuffix(filepath.Base(target), filepath.Ext(target))
			zipPath = filepath.Join(zipPath, base+"-redacted.zip")
		} else if destInfo, err := os.Stat(zipPath); err == nil && destInfo.IsDir() {
			base := strings.TrimSuffix(filepath.Base(target), filepath.Ext(target))
			zipPath = filepath.Join(zipPath, base+"-redacted.zip")
		}

		if err := os.MkdirAll(filepath.Dir(zipPath), 0o700); err != nil && filepath.Dir(zipPath) != "." {
			return fail("netops backup redact: creating directory %s: %v", filepath.Dir(zipPath), err)
		}

		zf, err := os.OpenFile(zipPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fail("netops backup redact: creating zip %s: %v", zipPath, err)
		}
		defer zf.Close()

		zw := zip.NewWriter(zf)
		header := &zip.FileHeader{
			Name:     filepath.Base(target),
			Method:   zip.Deflate,
			Modified: info.ModTime(),
		}
		w, err := zw.CreateHeader(header)
		if err != nil {
			return fail("netops backup redact: writing zip header: %v", err)
		}
		if _, err := w.Write(redactedData); err != nil {
			return fail("netops backup redact: writing file to zip: %v", err)
		}
		if err := zw.Close(); err != nil {
			return fail("netops backup redact: finalizing zip: %v", err)
		}
		if verbose {
			fmt.Fprintf(stderr, "Wrote redacted zip archive %s\n", zipPath)
		}
		return task.ExitOK
	}

	if output == "" {
		if _, err := stdout.Write(redactedData); err != nil {
			return fail("netops backup redact: writing stdout: %v", err)
		}
		return task.ExitOK
	}

	destPath := output
	if strings.HasSuffix(destPath, "/") || strings.HasSuffix(destPath, "\\") {
		destPath = filepath.Join(destPath, filepath.Base(target))
	} else if destInfo, err := os.Stat(destPath); err == nil && destInfo.IsDir() {
		destPath = filepath.Join(destPath, filepath.Base(target))
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil && filepath.Dir(destPath) != "." {
		return fail("netops backup redact: creating directory %s: %v", filepath.Dir(destPath), err)
	}
	if err := backup.WriteFileAtomic(destPath, redactedData, 0o600); err != nil {
		return fail("netops backup redact: writing %s: %v", destPath, err)
	}
	if verbose {
		fmt.Fprintf(stderr, "Wrote redacted file %s\n", destPath)
	}
	return task.ExitOK
}

func redactDirectory(target string, output string, zipOutput, inPlace, verbose bool, stdout, stderr io.Writer, fail func(string, ...any) int) int {
	cleanTarget := filepath.Clean(target)

	if inPlace {
		count := 0
		// #nosec G122 // directory traversal for CLI backup archive
		err := filepath.Walk(cleanTarget, func(path string, f os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if f.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("reading %s: %w", path, err)
			}
			if !isBinaryContent(data) {
				redacted := []byte(redact.Config(string(data)))
				if err := backup.WriteFileAtomic(path, redacted, f.Mode().Perm()); err != nil {
					return fmt.Errorf("writing %s: %w", path, err)
				}
				count++
			}
			return nil
		})
		if err != nil {
			return fail("netops backup redact: %v", err)
		}
		if verbose {
			fmt.Fprintf(stderr, "Redacted %d file(s) in %s in-place\n", count, cleanTarget)
		}
		return task.ExitOK
	}

	isZip := zipOutput || strings.HasSuffix(strings.ToLower(output), ".zip")
	destPath := output
	if destPath == "" {
		if isZip {
			destPath = cleanTarget + "-redacted.zip"
		} else {
			destPath = cleanTarget + "-redacted"
		}
	}

	if isZip {
		if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil && filepath.Dir(destPath) != "." {
			return fail("netops backup redact: creating directory %s: %v", filepath.Dir(destPath), err)
		}
		zf, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fail("netops backup redact: creating zip %s: %v", destPath, err)
		}
		defer zf.Close()

		zw := zip.NewWriter(zf)
		count := 0
		// #nosec G122 // directory traversal for CLI backup archive
		err = filepath.Walk(cleanTarget, func(path string, f os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if f.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(cleanTarget, path)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("reading %s: %w", path, err)
			}
			if !isBinaryContent(data) {
				data = []byte(redact.Config(string(data)))
			}
			header := &zip.FileHeader{
				Name:     filepath.ToSlash(rel),
				Method:   zip.Deflate,
				Modified: f.ModTime(),
			}
			w, err := zw.CreateHeader(header)
			if err != nil {
				return fmt.Errorf("writing zip header for %s: %w", rel, err)
			}
			if _, err := w.Write(data); err != nil {
				return fmt.Errorf("writing data to zip for %s: %w", rel, err)
			}
			count++
			return nil
		})
		if err != nil {
			_ = zw.Close()
			return fail("netops backup redact: %v", err)
		}
		if err := zw.Close(); err != nil {
			return fail("netops backup redact: finalizing zip %s: %v", destPath, err)
		}
		if verbose {
			fmt.Fprintf(stderr, "Wrote %d redacted file(s) to zip archive %s\n", count, destPath)
		}
		return task.ExitOK
	}

	// Normal directory output
	count := 0
	// #nosec G122 // directory traversal for CLI backup archive
	err := filepath.Walk(cleanTarget, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(cleanTarget, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(destPath, rel)
		if f.IsDir() {
			return os.MkdirAll(dest, 0o700)
		}

		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		if !isBinaryContent(data) {
			data = []byte(redact.Config(string(data)))
		}
		if err := backup.WriteFileAtomic(dest, data, 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", dest, err)
		}
		count++
		return nil
	})
	if err != nil {
		return fail("netops backup redact: %v", err)
	}
	if verbose {
		fmt.Fprintf(stderr, "Wrote %d redacted file(s) to directory %s\n", count, destPath)
	}
	return task.ExitOK
}
