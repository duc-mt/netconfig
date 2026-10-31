// ==============================================================================
// File name:     incident.go
// Description:   Telegram alerts for "netops log": auto-triage incidents,
//                device poll failures/recoveries and custom notices, with a
//                per-alert cooldown so a flapping device cannot flood a chat.
// License:       MIT
// ==============================================================================

package notifier

import (
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"

	"netops/internal/credentials"
	"netops/internal/log/collector"
)

// DefaultLogCooldownSeconds is the per-alert cooldown "netops log" applies when
// TELEGRAM_COOLDOWN_SECONDS is not set.
const DefaultLogCooldownSeconds = 300

// DefaultLogMinSeverity is the alert threshold used when TELEGRAM_MIN_SEVERITY
// is not set.
const DefaultLogMinSeverity = "warning"

// Logger receives the notifier's own diagnostics: failed deliveries, throttled
// alerts and messages dropped because the queue is full. collector.Logger
// satisfies it.
type Logger interface {
	Info(format string, args ...any)
	Warn(format string, args ...any)
}

// ConfigForLog loads the Telegram settings for "netops log". It reads the same
// TELEGRAM_* variables as ConfigFromResolver, but alerts are throttled by
// default (DefaultLogCooldownSeconds) because a log monitor can raise the same
// incident many times.
func ConfigForLog(resolver *credentials.Resolver) TelegramConfig {
	cfg := ConfigFromResolver(resolver)
	get := resolverLookup(resolver)

	cfg.CooldownSeconds = DefaultLogCooldownSeconds
	if v := get("TELEGRAM_COOLDOWN_SECONDS"); v != "" {
		if cd, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && cd >= 0 {
			cfg.CooldownSeconds = cd
		}
	}
	cfg.MinSeverity = strings.ToLower(strings.TrimSpace(get("TELEGRAM_MIN_SEVERITY")))
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = DefaultLogMinSeverity
	}
	return cfg
}

// shouldThrottle reports whether an alert with this key was already sent within
// the configured cooldown, and otherwise records it as sent now.
func (tn *TelegramNotifier) shouldThrottle(key string) bool {
	if tn.cfg.CooldownSeconds <= 0 {
		return false
	}
	tn.cooldownMu.Lock()
	defer tn.cooldownMu.Unlock()

	now := time.Now()
	if last, ok := tn.lastSent[key]; ok {
		if now.Sub(last) < time.Duration(tn.cfg.CooldownSeconds)*time.Second {
			return true
		}
	}
	tn.lastSent[key] = now
	return false
}

// OnIncident implements triage.Hook.
func (tn *TelegramNotifier) OnIncident(report collector.IncidentReport, _ string) {
	if tn == nil {
		return
	}

	key := fmt.Sprintf("incident:%s:%s", report.Hostname, report.TriggerLog.Event)
	if tn.shouldThrottle(key) {
		if tn.logger != nil {
			tn.logger.Info("telegram: throttled incident alert for %s %s", report.Hostname, report.TriggerLog.Event)
		}
		return
	}

	var sb strings.Builder
	sb.WriteString("🚨 <b>[NETOPS LOG INCIDENT] Auto-Triage Captured</b>\n\n")
	fmt.Fprintf(&sb, "• <b>Device:</b> <code>%s</code>\n", html.EscapeString(report.Hostname))
	fmt.Fprintf(&sb, "• <b>Event:</b> <code>%s</code>\n", html.EscapeString(report.TriggerLog.Event))
	if report.TriggerLog.Object != "" {
		fmt.Fprintf(&sb, "• <b>Target:</b> <code>%s</code>\n", html.EscapeString(report.TriggerLog.Object))
	}
	fmt.Fprintf(&sb, "• <b>Playbook:</b> <code>%s</code>\n", html.EscapeString(report.Playbook))
	fmt.Fprintf(&sb, "• <b>Time:</b> %s\n", report.Timestamp.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&sb, "• <b>Incident ID:</b> <code>%s</code>\n", report.ID)

	if len(report.TriageHints) > 0 {
		sb.WriteString("\n🔍 <b>Root Cause Hints:</b>\n")
		for _, h := range report.TriageHints {
			fmt.Fprintf(&sb, "  ▸ <i>%s</i>\n", html.EscapeString(h))
		}
	}

	if len(report.Diagnostics) > 0 {
		sb.WriteString("\n📋 <b>Diagnostic Summary:</b>\n")
		for _, d := range report.Diagnostics {
			fmt.Fprintf(&sb, "▸ <code>%s</code>", html.EscapeString(d.Command))
			if d.Error != "" {
				fmt.Fprintf(&sb, " (Error: %s)\n", html.EscapeString(d.Error))
			} else {
				fmt.Fprintf(&sb, " (%d ms)\n", d.DurationMs)
				lines := strings.Split(strings.TrimSpace(d.Output), "\n")
				if len(lines) > 6 {
					lines = append(lines[:6], "... [truncated]")
				}
				snippet := strings.Join(lines, "\n")
				fmt.Fprintf(&sb, "<pre>%s</pre>\n", html.EscapeString(snippet))
			}
		}
	}

	select {
	case tn.asyncCh <- sb.String():
	default:
		if tn.logger != nil {
			tn.logger.Warn("telegram: alert queue full, dropping incident %s", report.ID)
		}
	}
}

// SendDeviceHealth alerts when a device poll fails or recovers.
func (tn *TelegramNotifier) SendDeviceHealth(device string, ok bool, detail string) {
	if tn == nil {
		return
	}

	stateKey := "fail"
	if ok {
		stateKey = "ok"
	}
	key := fmt.Sprintf("health:%s:%s", device, stateKey)
	if tn.shouldThrottle(key) {
		return
	}

	var sb strings.Builder
	if ok {
		sb.WriteString("✅ <b>[NETOPS LOG RECOVERED] Device Poll Succeeded</b>\n\n")
		fmt.Fprintf(&sb, "• <b>Device:</b> <code>%s</code>\n", html.EscapeString(device))
		sb.WriteString("• <b>Status:</b> Normal SSH polling resumed\n")
		fmt.Fprintf(&sb, "• <b>Time:</b> %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	} else {
		sb.WriteString("🔴 <b>[NETOPS LOG ALERT] Device Poll Failed</b>\n\n")
		fmt.Fprintf(&sb, "• <b>Device:</b> <code>%s</code>\n", html.EscapeString(device))
		fmt.Fprintf(&sb, "• <b>Error:</b> <code>%s</code>\n", html.EscapeString(detail))
		fmt.Fprintf(&sb, "• <b>Time:</b> %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	}

	select {
	case tn.asyncCh <- sb.String():
	default:
		if tn.logger != nil {
			tn.logger.Warn("telegram: alert queue full, dropping health alert for %s", device)
		}
	}
}

// SendCustomNotification sends an arbitrary formatted message.
func (tn *TelegramNotifier) SendCustomNotification(title, body string) {
	if tn == nil {
		return
	}
	msg := fmt.Sprintf("📢 <b>%s</b>\n\n%s", html.EscapeString(title), body)
	select {
	case tn.asyncCh <- msg:
	default:
	}
}
