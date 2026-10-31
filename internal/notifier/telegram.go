// ==============================================================================
// Package notifier: Telegram and webhook notifications for netops.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-26
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/internal/credentials"
	"netops/internal/task"
)

// TelegramConfig defines the configuration for sending alerts to Telegram.
type TelegramConfig struct {
	Enabled         bool
	BotToken        string
	ChatID          string
	ThreadID        int
	Silent          bool
	ProxyURL        string
	CooldownSeconds int
	MinSeverity     string // "netops log" alert threshold (TELEGRAM_MIN_SEVERITY); see ConfigForLog
}

// ConfigFromResolver loads TelegramConfig from credentials.Resolver or process environment.
func ConfigFromResolver(resolver *credentials.Resolver) TelegramConfig {
	get := resolverLookup(resolver)

	enabled := false
	if v := get("TELEGRAM_ENABLED"); v != "" {
		v = strings.ToLower(strings.TrimSpace(v))
		enabled = (v == "true" || v == "1" || v == "yes" || v == "on")
	}

	threadID := 0
	if v := get("TELEGRAM_MESSAGE_THREAD_ID"); v != "" {
		if id, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			threadID = id
		}
	}

	cooldown := 0
	if v := get("TELEGRAM_COOLDOWN_SECONDS"); v != "" {
		if cd, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && cd >= 0 {
			cooldown = cd
		}
	}

	silent := false
	if v := get("TELEGRAM_SILENT"); v != "" {
		v = strings.ToLower(strings.TrimSpace(v))
		silent = (v == "true" || v == "1" || v == "yes" || v == "on")
	}

	return TelegramConfig{
		Enabled:         enabled,
		BotToken:        strings.TrimSpace(get("TELEGRAM_BOT_TOKEN")),
		ChatID:          strings.TrimSpace(get("TELEGRAM_CHAT_ID")),
		ThreadID:        threadID,
		Silent:          silent,
		ProxyURL:        strings.TrimSpace(get("TELEGRAM_PROXY_URL")),
		CooldownSeconds: cooldown,
	}
}

// resolverLookup returns a function that reads a setting from the resolver's
// .env values, then its environment lookup, then the process environment.
func resolverLookup(resolver *credentials.Resolver) func(string) string {
	return func(key string) string {
		if resolver != nil {
			if v, ok := resolver.DotEnv[key]; ok && v != "" {
				return v
			}
			if resolver.LookupEnv != nil {
				if v, ok := resolver.LookupEnv(key); ok && v != "" {
					return v
				}
			}
		}
		return os.Getenv(key)
	}
}

// ConfigFromEnv loads TelegramConfig directly from environment variables.
func ConfigFromEnv() TelegramConfig {
	return ConfigFromResolver(nil)
}

// TelegramNotifier dispatches notifications to Telegram channels.
type TelegramNotifier struct {
	cfg     TelegramConfig
	client  *http.Client
	baseURL string
	asyncCh chan string
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc

	// Used by the "netops log" alerts (incident.go).
	logger     Logger
	cooldownMu sync.Mutex
	lastSent   map[string]time.Time
}

// NewTelegram creates a TelegramNotifier. Returns nil if not enabled or tokens are missing.
func NewTelegram(cfg TelegramConfig) *TelegramNotifier {
	return NewTelegramWithLogger(cfg, nil)
}

// NewTelegramWithLogger is NewTelegram with a logger that receives delivery
// failures, throttled alerts and dropped messages (nil discards them).
func NewTelegramWithLogger(cfg TelegramConfig, log Logger) *TelegramNotifier {
	if !cfg.Enabled || cfg.BotToken == "" || cfg.ChatID == "" {
		return nil
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if cfg.ProxyURL != "" {
		if u, err := url.Parse(cfg.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		} else if log != nil {
			log.Warn("telegram: invalid proxy URL %q: %v", cfg.ProxyURL, err)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	tn := &TelegramNotifier{
		cfg:     cfg,
		client:  client,
		baseURL: "https://api.telegram.org/bot" + cfg.BotToken,
		asyncCh: make(chan string, 100),
		ctx:     ctx,
		cancel:  cancel,

		logger:   log,
		lastSent: make(map[string]time.Time),
	}

	tn.wg.Add(1)
	go tn.worker()

	return tn
}

// SetBaseURL overrides the API endpoint for unit testing.
func (tn *TelegramNotifier) SetBaseURL(u string) {
	tn.baseURL = strings.TrimRight(u, "/")
}

// Close gracefully flushes the queue and waits for worker shutdown.
func (tn *TelegramNotifier) Close() {
	if tn == nil {
		return
	}
	tn.cancel()
	close(tn.asyncCh)
	tn.wg.Wait()
}

func (tn *TelegramNotifier) worker() {
	defer tn.wg.Done()
	for msg := range tn.asyncCh {
		if err := tn.sendRaw(context.Background(), msg); err != nil && tn.logger != nil {
			tn.logger.Warn("telegram send failed: %v", err)
		}
	}
}

type telegramPayload struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode"`
	DisableNotification   bool   `json:"disable_notification,omitempty"`
	MessageThreadID       int    `json:"message_thread_id,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

func (tn *TelegramNotifier) sendRaw(ctx context.Context, text string) error {
	payload := telegramPayload{
		ChatID:                tn.cfg.ChatID,
		Text:                  text,
		ParseMode:             "HTML",
		DisableNotification:   tn.cfg.Silent,
		MessageThreadID:       tn.cfg.ThreadID,
		DisableWebPagePreview: true,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoint := tn.baseURL + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tn.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Description string `json:"description"`
			ErrorCode   int    `json:"error_code"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("telegram api error %d: %s", resp.StatusCode, errResp.Description)
	}

	return nil
}

// SendSync sends a synchronous message (e.g. for CLI test command).
func (tn *TelegramNotifier) SendSync(ctx context.Context, text string) error {
	return tn.sendRaw(ctx, text)
}

// BackupSummaryMetrics holds metrics from a backup run.
type BackupSummaryMetrics struct {
	TotalDevices int
	Succeeded    int
	Failed       int
	Changed      int
	Unchanged    int
	Drifted      int
	Duration     time.Duration
	DryRun       bool
	Failures     []string
}

// SendBackupSummary formats and queues a backup run completion report.
func (tn *TelegramNotifier) SendBackupSummary(m BackupSummaryMetrics) {
	if tn == nil {
		return
	}

	icon := "📦"
	title := "NETOPS BACKUP COMPLETED"
	if m.DryRun {
		title = "[DRY-RUN] NETOPS BACKUP"
		icon = "🟡"
	} else if m.Failed > 0 {
		icon = "⚠️"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s <b>[%s]</b>\n\n", icon, title))
	sb.WriteString(fmt.Sprintf("• <b>Total Devices:</b> %d\n", m.TotalDevices))
	sb.WriteString(fmt.Sprintf("• <b>Succeeded:</b> %d\n", m.Succeeded))
	if m.Failed > 0 {
		sb.WriteString(fmt.Sprintf("• <b>Failed:</b> <code>%d</code>\n", m.Failed))
	}
	if m.Changed > 0 {
		sb.WriteString(fmt.Sprintf("• <b>Changes Detected:</b> <code>%d</code> device(s)\n", m.Changed))
	}
	if m.Drifted > 0 {
		sb.WriteString(fmt.Sprintf("• <b>Compliance Drift:</b> <code>%d</code> device(s)\n", m.Drifted))
	}
	sb.WriteString(fmt.Sprintf("• <b>Duration:</b> %s\n", m.Duration.Round(100*time.Millisecond)))
	sb.WriteString(fmt.Sprintf("• <b>Time:</b> %s\n", time.Now().Format("2006-01-02 15:04:05 MST")))

	if len(m.Failures) > 0 {
		sb.WriteString("\n🔴 <b>Failed Devices:</b>\n")
		for i, f := range m.Failures {
			if i >= 10 {
				sb.WriteString(fmt.Sprintf("  <i>...and %d more</i>\n", len(m.Failures)-10))
				break
			}
			sb.WriteString(fmt.Sprintf("  ▸ <code>%s</code>\n", html.EscapeString(f)))
		}
	}

	select {
	case tn.asyncCh <- sb.String():
	default:
	}
}

// SendTaskSummary formats and queues a configuration run summary.
func (tn *TelegramNotifier) SendTaskSummary(opName string, sum task.Summary, dryRun bool) {
	if tn == nil {
		return
	}

	icon := "🚀"
	prefix := "NETOPS"
	if dryRun {
		icon = "🟡"
		prefix = "[DRY-RUN] NETOPS"
	} else if sum.Failed > 0 {
		icon = "⚠️"
	}

	total := len(sum.Results)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s <b>[%s %s]</b>\n\n", icon, prefix, strings.ToUpper(html.EscapeString(opName))))
	sb.WriteString(fmt.Sprintf("• <b>Total Devices:</b> %d\n", total))
	sb.WriteString(fmt.Sprintf("• <b>Succeeded:</b> %d\n", sum.Succeeded))
	if sum.Failed > 0 {
		sb.WriteString(fmt.Sprintf("• <b>Failed:</b> <code>%d</code>\n", sum.Failed))
	}
	if sum.Skipped > 0 {
		sb.WriteString(fmt.Sprintf("• <b>Skipped:</b> %d\n", sum.Skipped))
	}
	sb.WriteString(fmt.Sprintf("• <b>Duration:</b> %s\n", sum.Duration.Round(100*time.Millisecond)))
	sb.WriteString(fmt.Sprintf("• <b>Time:</b> %s\n", time.Now().Format("2006-01-02 15:04:05 MST")))

	if len(sum.ByCategory) > 0 {
		sb.WriteString("\n🔴 <b>Issues by Category:</b>\n")
		for cat, hosts := range sum.ByCategory {
			sb.WriteString(fmt.Sprintf("  ▸ <b>%s:</b> %s\n", html.EscapeString(string(cat)), html.EscapeString(strings.Join(hosts, ", "))))
		}
	}

	select {
	case tn.asyncCh <- sb.String():
	default:
	}
}
