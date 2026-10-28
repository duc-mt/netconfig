// ==============================================================================
// File name:     cve.go
// Description:   Telegram alerts for "netops cve": message formatting (HTML,
//                split to Telegram's size limit) and delivery.
// License:       MIT
// ==============================================================================

package notifier

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"
	"unicode/utf8"

	"netops/internal/cve"
)

const (
	// Telegram rejects messages above 4096 characters; stay well clear of it.
	telegramChunkLimit = 3800
	// An alert is a pointer to the report, not the report: a device lists its
	// worst advisories only, and a run of hundreds of devices is cut off after a
	// few messages instead of flooding the chat (Telegram also rate-limits it).
	cveMaxAdvisoriesPerDevice = 5
	cveMaxMessages            = 4
	cveFieldClip              = 60
)

// cveMessageGap is the pause between the messages of one alert (Telegram allows
// about one message per second to a chat). A variable so tests need not wait.
var cveMessageGap = 1100 * time.Millisecond

// newTelegram creates the notifier; tests replace it to point at a mock API.
var newTelegram = NewTelegram

// ErrTelegramNotConfigured means Telegram is disabled or lacks a bot token or
// chat ID, so nothing can be sent.
var ErrTelegramNotConfigured = errors.New("telegram is not enabled or TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID is missing")

// FormatCVEAlert renders the devices that have advisories as Telegram HTML
// messages (usually one; more when the text would exceed Telegram's limit). It
// returns nil when there is nothing to report. Devices without advisories,
// including ones that could not be checked, are not part of an alert.
//
//	🚨 <b>NetOps CVE Alert Summary</b>
//	Found <b>3</b> vulnerabilities across <b>1</b> device:
//	• <b>router-01</b> (cisco-ios-xe 17.6.1): <b>2 Critical</b>, <b>1 High</b>
//	  - <code>CVE-2023-20198</code> (CVSS 10.0) [Fixed: 17.6.2]
func FormatCVEAlert(results []cve.DeviceCVEResult) []string {
	var units []string
	total, devices := 0, 0
	for _, r := range results {
		if len(r.Advisories) == 0 {
			continue
		}
		total += len(r.Advisories)
		devices++
		units = append(units, cveDeviceBlock(r))
	}
	if total == 0 {
		return nil
	}

	header := fmt.Sprintf("🚨 <b>NetOps CVE Alert Summary</b>\nFound <b>%d</b> %s across <b>%d</b> %s:\n",
		total, plural(total, "vulnerability", "vulnerabilities"), devices, plural(devices, "device", "devices"))
	const continued = "🚨 <b>NetOps CVE Alert</b> (continued)\n"

	type chunk struct {
		text    strings.Builder
		devices int
	}
	cur := &chunk{}
	cur.text.WriteString(header)
	chunks := []*chunk{cur}
	for _, u := range units {
		if cur.devices > 0 && utf8.RuneCountInString(cur.text.String())+utf8.RuneCountInString(u) > telegramChunkLimit {
			cur = &chunk{}
			cur.text.WriteString(continued)
			chunks = append(chunks, cur)
		}
		cur.text.WriteString(u)
		cur.devices++
	}

	dropped := 0
	if len(chunks) > cveMaxMessages {
		for _, c := range chunks[cveMaxMessages:] {
			dropped += c.devices
		}
		chunks = chunks[:cveMaxMessages]
		fmt.Fprintf(&chunks[cveMaxMessages-1].text, "<i>… %d more %s not shown; see the CSV/JSON report.</i>\n",
			dropped, plural(dropped, "device", "devices"))
	}
	out := make([]string, len(chunks))
	for i, c := range chunks {
		out[i] = strings.TrimRight(c.text.String(), "\n")
	}
	return out
}

func cveDeviceBlock(r cve.DeviceCVEResult) string {
	name := r.Hostname
	if name == "" {
		name = r.IP
	}
	if name == "" {
		name = "(unnamed)"
	}
	var counts []string
	for _, s := range []struct {
		sev   cve.Severity
		label string
	}{
		{cve.SeverityCritical, "Critical"}, {cve.SeverityHigh, "High"}, {cve.SeverityMedium, "Medium"},
		{cve.SeverityLow, "Low"}, {cve.SeverityUnknown, "Unscored"},
	} {
		if n := r.Count(s.sev); n > 0 {
			counts = append(counts, fmt.Sprintf("<b>%d %s</b>", n, s.label))
		}
	}
	// An advisory carrying a severity this code does not know is still counted.
	if len(counts) == 0 {
		counts = append(counts, fmt.Sprintf("<b>%d Unscored</b>", len(r.Advisories)))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "• <b>%s</b> (%s %s): %s\n", esc(name), esc(r.OS), esc(r.Version), strings.Join(counts, ", "))
	for i, a := range r.Advisories {
		if i == cveMaxAdvisoriesPerDevice {
			fmt.Fprintf(&b, "  … and %d more\n", len(r.Advisories)-i)
			break
		}
		cvss, fixed := "n/a", "unknown"
		if a.CVSS > 0 {
			cvss = fmt.Sprintf("%.1f", a.CVSS)
		}
		if a.FixedVer != "" {
			fixed = a.FixedVer
		}
		fmt.Fprintf(&b, "  - <code>%s</code> (CVSS %s) [Fixed: %s]\n", esc(a.ID), esc(cvss), esc(fixed))
	}
	return b.String()
}

// esc escapes text for Telegram HTML and keeps one field from dominating a message.
func esc(s string) string {
	if r := []rune(s); len(r) > cveFieldClip {
		s = string(r[:cveFieldClip-1]) + "…"
	}
	return html.EscapeString(s)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// SendTelegram delivers one already formatted HTML message with a short-lived
// notifier. It fails with ErrTelegramNotConfigured when Telegram is not set up.
func SendTelegram(ctx context.Context, cfg TelegramConfig, msg string) error {
	tn := newTelegram(cfg)
	if tn == nil {
		return ErrTelegramNotConfigured
	}
	defer tn.Close()
	return sendAll(ctx, tn, cfg.BotToken, []string{msg})
}

// SendCVEAlert formats results (see FormatCVEAlert) and sends the messages in
// order. With nothing to report it sends nothing and returns nil.
func SendCVEAlert(ctx context.Context, cfg TelegramConfig, results []cve.DeviceCVEResult) error {
	msgs := FormatCVEAlert(results)
	if len(msgs) == 0 {
		return nil
	}
	tn := newTelegram(cfg)
	if tn == nil {
		return ErrTelegramNotConfigured
	}
	defer tn.Close()
	return sendAll(ctx, tn, cfg.BotToken, msgs)
}

func sendAll(ctx context.Context, tn *TelegramNotifier, token string, msgs []string) error {
	for i, m := range msgs {
		if i > 0 {
			t := time.NewTimer(cveMessageGap)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
		if err := tn.SendSync(ctx, m); err != nil {
			err = redactToken(err, token)
			if len(msgs) > 1 {
				return fmt.Errorf("message %d of %d: %w", i+1, len(msgs), err)
			}
			return err
		}
	}
	return nil
}

// redactToken removes the bot token from an error. The Telegram API URL carries
// the token, and a failed HTTP request reports that URL.
func redactToken(err error, token string) error {
	if token == "" || !strings.Contains(err.Error(), token) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "***"))
}
