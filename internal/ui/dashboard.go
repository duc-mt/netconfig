// Package ui implements terminal user interface components for netconfig,
// including a live multi-line ANSI terminal progress dashboard with zero external dependencies.
package ui

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"netops/internal/inventory"
	"netops/internal/task"
	"netops/internal/vendor"
)

type activeDevice struct {
	dev       inventory.Device
	stepKind  vendor.StepKind
	stepLine  string
	startedAt time.Time
}

// Dashboard renders a dynamic live ANSI progress status display during execution.
type Dashboard struct {
	mu       sync.Mutex
	stopOnce sync.Once
	out      io.Writer

	totalDevices int
	succeeded    int
	failed       int
	skipped      int
	completed    int

	batchNum     int
	totalBatches int
	batchCount   int
	isCanary     bool
	canaryPassed bool

	active map[string]*activeDevice
	order  []string // insertion order of active devices

	startTime time.Time
	ticker    *time.Ticker
	stopChan  chan struct{}
	lastLines int
	enabled   bool
	width     int
}

// Config sets up the Dashboard.
type Config struct {
	Writer       io.Writer
	TotalDevices int
	Width        int
	Enabled      bool
}

// New creates and starts a Dashboard.
func New(cfg Config) *Dashboard {
	if cfg.Width <= 0 {
		cfg.Width = 80
	}
	d := &Dashboard{
		out:          cfg.Writer,
		totalDevices: cfg.TotalDevices,
		width:        cfg.Width,
		enabled:      cfg.Enabled,
		active:       make(map[string]*activeDevice),
		startTime:    time.Now(),
		stopChan:     make(chan struct{}),
	}
	if d.enabled {
		d.ticker = time.NewTicker(100 * time.Millisecond)
		go d.loop()
	}
	return d
}

func (d *Dashboard) loop() {
	for {
		select {
		case <-d.stopChan:
			return
		case <-d.ticker.C:
			d.mu.Lock()
			d.renderLocked()
			d.mu.Unlock()
		}
	}
}

// Stop halts the dashboard ticker and clears the rendered dashboard lines from the terminal.
func (d *Dashboard) Stop() {
	if !d.enabled {
		return
	}
	d.stopOnce.Do(func() {
		if d.ticker != nil {
			d.ticker.Stop()
		}
		close(d.stopChan)
	})
	d.mu.Lock()
	defer d.mu.Unlock()
	d.clearLocked()
}

func (d *Dashboard) clearLocked() {
	if d.lastLines > 0 {
		// Move up and clear each line
		fmt.Fprintf(d.out, "\033[%dA", d.lastLines)
		for i := 0; i < d.lastLines; i++ {
			fmt.Fprint(d.out, "\r\033[2K\n")
		}
		fmt.Fprintf(d.out, "\033[%dA\r", d.lastLines)
		d.lastLines = 0
	}
}

// Log writes a message to the output stream above the dashboard, preserving the dashboard below.
func (d *Dashboard) Log(msg string) {
	if !d.enabled {
		fmt.Fprintln(d.out, msg)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	d.clearLocked()
	fmt.Fprintln(d.out, msg)
	d.renderLocked()
}

// OnBatchStart implements task.StatusObserver.
func (d *Dashboard) OnBatchStart(batch int, totalBatches int, count int, isCanary bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.batchNum = batch
	d.totalBatches = totalBatches
	d.batchCount = count
	d.isCanary = isCanary
	if !isCanary && batch > 1 {
		d.canaryPassed = true
	}
	d.renderLocked()
}

// OnDeviceStart implements task.StatusObserver.
func (d *Dashboard) OnDeviceStart(dev inventory.Device) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.active[dev.Hostname] = &activeDevice{
		dev:       dev,
		stepKind:  vendor.StepProbe,
		stepLine:  "connecting",
		startedAt: time.Now(),
	}
	d.order = append(d.order, dev.Hostname)
	d.renderLocked()
}

// OnDeviceStep implements task.StatusObserver.
func (d *Dashboard) OnDeviceStep(dev inventory.Device, step vendor.StepKind, line string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if ad, ok := d.active[dev.Hostname]; ok {
		ad.stepKind = step
		ad.stepLine = line
	}
	d.renderLocked()
}

// OnDeviceDone implements task.StatusObserver.
func (d *Dashboard) OnDeviceDone(res task.Result) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.active, res.Device.Hostname)
	var newOrder []string
	for _, h := range d.order {
		if h != res.Device.Hostname {
			newOrder = append(newOrder, h)
		}
	}
	d.order = newOrder

	d.completed++
	switch res.Status {
	case task.StatusSucceeded:
		d.succeeded++
	case task.StatusFailed:
		d.failed++
	case task.StatusSkipped:
		d.skipped++
	}
	d.renderLocked()
}

func (d *Dashboard) renderLocked() {
	if !d.enabled {
		return
	}

	lines := d.buildLines()

	// If we previously drew lines, move cursor up to redraw
	if d.lastLines > 0 {
		fmt.Fprintf(d.out, "\033[%dA", d.lastLines)
	}

	for _, l := range lines {
		// Truncate to terminal width and clear line
		trimmed := truncate(l, d.width)
		fmt.Fprintf(d.out, "\r%s\033[K\n", trimmed)
	}

	d.lastLines = len(lines)
}

func (d *Dashboard) buildLines() []string {
	var lines []string

	elapsed := time.Since(d.startTime).Round(time.Second)
	batchInfo := ""
	if d.totalBatches > 1 {
		if d.isCanary {
			batchInfo = fmt.Sprintf(" [Canary: %d dev]", d.batchCount)
		} else {
			batchInfo = fmt.Sprintf(" [Batch %d/%d]", d.batchNum, d.totalBatches)
		}
	}

	// Line 1: Header summary
	lines = append(lines, fmt.Sprintf("\x1b[1mnetops\x1b[0m%s [Active: %d] [Elapsed: %02d:%02d]",
		batchInfo, len(d.active), int(elapsed.Minutes()), int(elapsed.Seconds())%60))

	// Line 2: Progress bar
	percent := 0
	if d.totalDevices > 0 {
		percent = (d.completed * 100) / d.totalDevices
	}
	bar := renderBar(percent, 24)
	lines = append(lines, fmt.Sprintf("%s %d/%d (%d%%) | \x1b[32m%d OK\x1b[0m, \x1b[31m%d FAIL\x1b[0m, \x1b[33m%d SKIP\x1b[0m",
		bar, d.completed, d.totalDevices, percent, d.succeeded, d.failed, d.skipped))

	// Active devices (up to 6)
	maxActive := 6
	count := 0
	for _, h := range d.order {
		if count >= maxActive {
			break
		}
		ad, ok := d.active[h]
		if !ok {
			continue
		}
		duration := time.Since(ad.startedAt).Round(100 * time.Millisecond)
		cmdStr := ad.stepLine
		if len(cmdStr) > 30 {
			cmdStr = cmdStr[:27] + "..."
		}
		lines = append(lines, fmt.Sprintf("  \x1b[36m*\x1b[0m %-16s (%-8s) [%-9s] %-30s (%s)",
			ad.dev.Hostname, ad.dev.Vendor, ad.stepKind, cmdStr, duration))
		count++
	}
	if len(d.order) > maxActive {
		lines = append(lines, fmt.Sprintf("  ... and %d more in flight", len(d.order)-maxActive))
	}

	return lines
}

func renderBar(percent, width int) string {
	if width < 5 {
		width = 10
	}
	filled := (percent * width) / 100
	if filled > width {
		filled = width
	}
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < filled; i++ {
		b.WriteByte('=')
	}
	if filled < width {
		b.WriteByte('>')
		for i := filled + 1; i < width; i++ {
			b.WriteByte('-')
		}
	}
	b.WriteString("]")
	return b.String()
}

func truncate(s string, max int) string {
	if max <= 0 {
		return s
	}
	// Measure length ignoring ANSI escapes
	plainLen := 0
	inEsc := false
	for _, r := range s {
		if r == '\x1b' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		plainLen++
	}
	if plainLen <= max {
		return s
	}
	// Truncate plain characters
	var b strings.Builder
	cur := 0
	inEsc = false
	for _, r := range s {
		if r == '\x1b' {
			inEsc = true
			b.WriteRune(r)
			continue
		}
		if inEsc {
			b.WriteRune(r)
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		if cur >= max-3 {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
		cur++
	}
	if strings.Contains(s, "\x1b") {
		b.WriteString("\x1b[0m")
	}
	return b.String()
}
