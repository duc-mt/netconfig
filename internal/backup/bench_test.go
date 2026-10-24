// ==============================================================================
// File name:     bench_test.go
// Description:   Benchmarks for the backup engine's per-device hot paths.
// License:       MIT
// ==============================================================================
package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netconfig/internal/inventory"
	"netconfig/internal/redact"
	"netconfig/internal/vendor"
)

// benchConfig builds an IOS-like configuration of about n lines: interface
// blocks with repeated "!" separators, ACL entries and the odd secret, so line
// repetition is as realistic as it is in a real running-config.
func benchConfig(n int, variant int) string {
	var b strings.Builder
	b.WriteString("version 15.2\nhostname core-sw1\nenable secret 5 $1$abcd$XyZ123hashvalue\n!\n")
	for i := 0; b.Len() < n*28; i++ {
		fmt.Fprintf(&b, "interface GigabitEthernet0/%d\n description uplink-%d\n switchport mode access\n switchport access vlan %d\n!\n", i, i, 10+i%40)
		if i%7 == 0 {
			fmt.Fprintf(&b, "ip access-list extended ACL-%d\n permit tcp any host 10.0.%d.%d eq 443\n deny ip any any\n!\n", i, i%250, i%200)
		}
		if i%50 == 0 {
			fmt.Fprintf(&b, "snmp-server community public%d RO\n", i)
		}
	}
	// a handful of localised changes, as between two nightly backups
	out := b.String()
	for k := 0; k < variant; k++ {
		out = strings.Replace(out, fmt.Sprintf(" description uplink-%d\n", k*3+1), fmt.Sprintf(" description changed-%d\n", k*3+1), 1)
	}
	return out + "end\n"
}

func lineCount(s string) int { return strings.Count(s, "\n") }

func BenchmarkDiffConfig(b *testing.B) {
	for _, n := range []int{500, 2000, 5000, 9000} {
		before, after := benchConfig(n, 0), benchConfig(n, 5)
		b.Run(fmt.Sprintf("%dlines", lineCount(before)), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, _, _, ok := diffConfig(before, after); !ok {
					b.Skip("over the diff size cap")
				}
			}
		})
	}
}

func BenchmarkRedactConfig(b *testing.B) {
	cfg := benchConfig(10000, 0)
	b.SetBytes(int64(len(cfg)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = redact.Config(cfg)
	}
}

func BenchmarkVolatileFilter(b *testing.B) {
	cfg := benchConfig(10000, 0)
	f, _ := NewVolatileFilter(nil)
	b.SetBytes(int64(len(cfg)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = f.Apply("cisco", cfg)
	}
}

func BenchmarkAssessRisk(b *testing.B) {
	before, after := benchConfig(2000, 0), benchConfig(2000, 40)
	lines, _, _, _ := diffConfig(before, after)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = assessRiskSafe(lines)
	}
}

// BenchmarkProcessConfig is everything a device costs after its configuration
// has been fetched: redact, compare with the previous backup, diff, risk, save.
func BenchmarkProcessConfig(b *testing.B) {
	for _, n := range []int{2000, 8000} {
		before, after := benchConfig(n, 0), benchConfig(n, 8)
		b.Run(fmt.Sprintf("%dlines", lineCount(before)), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				out := b.TempDir()
				dev, profile := benchDevice()
				cfg := Config{OutputDir: out, RunName: "backup-2026-10-02-0100", Redact: true, ShowDiff: true, IgnoreVolatile: true}
				prev := Config{OutputDir: out, RunName: "backup-2026-10-01-0100", Redact: true}
				if _, err := save(dev, profile, redact.Config(before), prev); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				res := processConfig(dev, profile, after, cfg, Result{Device: dev})
				if res.Err != nil {
					b.Fatal(res.Err)
				}
			}
		})
	}
}

// BenchmarkFindAndPrune is the per-device directory work (find the previous
// backup, apply retention) with a realistic estate: every run's platform
// directory also holds the other devices' files.
func BenchmarkFindAndPrune(b *testing.B) {
	for _, tc := range []struct{ runs, siblings int }{{10, 0}, {10, 2000}, {100, 500}, {365, 0}} {
		b.Run(fmt.Sprintf("%druns_%ddevices", tc.runs, tc.siblings+1), func(b *testing.B) {
			root := b.TempDir()
			dev, profile := benchDevice()
			spec := archiveFor(profile)
			for r := 0; r < tc.runs; r++ {
				dir := filepath.Join(root, fmt.Sprintf("backup-2026-01-01-%04d", r), spec.Dir)
				_ = os.MkdirAll(dir, 0o755)
				write := func(name string) {
					p := filepath.Join(dir, name)
					_ = os.WriteFile(p, []byte("x"), 0o600)
					when := time.Now().Add(-time.Duration(tc.runs-r) * time.Hour)
					_ = os.Chtimes(p, when, when)
				}
				write(dev.Hostname + spec.Ext)
				for d := 0; d < tc.siblings; d++ {
					write(fmt.Sprintf("other%04d%s", d, spec.Ext))
				}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				findLatestBackup(root, dev, spec.Ext)
				pruneBackups(root, dev, spec.Ext, 1000, 0) // keeps everything: nothing to recreate
			}
		})
	}
}

// BenchmarkScanTree is "show" on a large estate: 2000 devices, 10 runs.
func BenchmarkScanTree(b *testing.B) {
	root := b.TempDir()
	for r := 0; r < 10; r++ {
		dir := filepath.Join(root, fmt.Sprintf("backup-2026-10-%02d-0100", r+1), "cisco_ios")
		_ = os.MkdirAll(dir, 0o755)
		for d := 0; d < 2000; d++ {
			_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("sw%04d.cfg", d)), []byte("x"), 0o600)
		}
	}
	b.Run("ListNodes", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if nodes, err := ListNodes(root); err != nil || len(nodes) != 2000 {
				b.Fatal(len(nodes), err)
			}
		}
	})
	b.Run("Latest", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := Latest(root, "sw1234", false); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func benchDevice() (inventory.Device, *vendor.Profile) {
	p, _ := vendor.Lookup("cisco")
	return inventory.Device{Hostname: "core-sw1", Address: "10.0.0.1", Port: 22, Vendor: p.Name}, p
}
