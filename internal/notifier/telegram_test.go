package notifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/internal/credentials"
	"netops/internal/task"
)

func TestTelegramNotifier_SendSync(t *testing.T) {
	var payload telegramPayload
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/sendMessage") {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	cfg := TelegramConfig{
		Enabled:  true,
		BotToken: "123:abc",
		ChatID:   "-100123",
		ThreadID: 99,
		Silent:   true,
	}

	tn := NewTelegram(cfg)
	if tn == nil {
		t.Fatal("expected non-nil notifier")
	}
	defer tn.Close()

	tn.SetBaseURL(srv.URL)

	if err := tn.SendSync(t.Context(), "hello netops"); err != nil {
		t.Fatalf("SendSync failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if payload.ChatID != "-100123" {
		t.Errorf("expected chat_id -100123, got %s", payload.ChatID)
	}
	if payload.MessageThreadID != 99 {
		t.Errorf("expected thread_id 99, got %d", payload.MessageThreadID)
	}
	if !payload.DisableNotification {
		t.Errorf("expected disable_notification true, got false")
	}
	if payload.Text != "hello netops" {
		t.Errorf("expected text 'hello netops', got %s", payload.Text)
	}
}

func TestTelegramNotifier_SendSync_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error_code": 400, "description": "chat not found"}`))
	}))
	defer srv.Close()

	cfg := TelegramConfig{
		Enabled:  true,
		BotToken: "123:abc",
		ChatID:   "-100123",
	}

	tn := NewTelegram(cfg)
	if tn == nil {
		t.Fatal("expected non-nil notifier")
	}
	defer tn.Close()

	tn.SetBaseURL(srv.URL)

	err := tn.SendSync(context.Background(), "test error")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "chat not found") {
		t.Errorf("unexpected error string: %v", err)
	}

	// Test unreachable server error
	tn.SetBaseURL("http://127.0.0.1:0")
	if err := tn.SendSync(context.Background(), "test net error"); err == nil {
		t.Error("expected network error, got nil")
	}
}

func TestTelegramNotifier_SendTaskSummary(t *testing.T) {
	var payload telegramPayload
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	cfg := TelegramConfig{
		Enabled:  true,
		BotToken: "123:abc",
		ChatID:   "-100123",
	}

	tn := NewTelegram(cfg)
	tn.SetBaseURL(srv.URL)
	defer tn.Close()

	sum := task.Summary{
		Results:   make([]task.Result, 10),
		Succeeded: 9,
		Failed:    1,
		Skipped:   2,
		Duration:  5 * time.Second,
		ByCategory: map[task.Category][]string{
			task.CatConnectFailed: {"SW-CORE"},
		},
	}

	tn.SendTaskSummary("config", sum, false)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	text := payload.Text
	mu.Unlock()

	if !strings.Contains(text, "NETOPS CONFIG") {
		t.Errorf("expected payload to contain 'NETOPS CONFIG', got: %s", text)
	}
	if !strings.Contains(text, "SW-CORE") {
		t.Errorf("expected payload to contain 'SW-CORE', got: %s", text)
	}
	if !strings.Contains(text, "Skipped:</b> 2") {
		t.Errorf("expected payload to contain 'Skipped:</b> 2', got: %s", text)
	}

	// Test dryRun variant
	tn.SendTaskSummary("config", sum, true)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	textDry := payload.Text
	mu.Unlock()

	if !strings.Contains(textDry, "[DRY-RUN] NETOPS") {
		t.Errorf("expected payload to contain '[DRY-RUN] NETOPS', got: %s", textDry)
	}

	// Nil notifier should not panic
	var nilTN *TelegramNotifier
	nilTN.SendTaskSummary("config", sum, false)
}

func TestTelegramNotifier_SendBackupSummary(t *testing.T) {
	var payload telegramPayload
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	cfg := TelegramConfig{
		Enabled:  true,
		BotToken: "123:abc",
		ChatID:   "-100123",
	}

	tn := NewTelegram(cfg)
	tn.SetBaseURL(srv.URL)
	defer tn.Close()

	failures := make([]string, 12)
	for i := 0; i < 12; i++ {
		failures[i] = "switch-" + string(rune('a'+i))
	}

	m := BackupSummaryMetrics{
		TotalDevices: 20,
		Succeeded:    8,
		Failed:       12,
		Changed:      3,
		Drifted:      1,
		Duration:     10 * time.Second,
		DryRun:       false,
		Failures:     failures,
	}

	tn.SendBackupSummary(m)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	text := payload.Text
	mu.Unlock()

	if !strings.Contains(text, "NETOPS BACKUP COMPLETED") {
		t.Errorf("expected text to contain 'NETOPS BACKUP COMPLETED', got: %s", text)
	}
	if !strings.Contains(text, "Changes Detected:</b> <code>3</code>") {
		t.Errorf("expected text to contain Changes Detected, got: %s", text)
	}
	if !strings.Contains(text, "Compliance Drift:</b> <code>1</code>") {
		t.Errorf("expected text to contain Compliance Drift, got: %s", text)
	}
	if !strings.Contains(text, "...and 2 more") {
		t.Errorf("expected text to contain '...and 2 more', got: %s", text)
	}

	// Test DryRun variant
	m.DryRun = true
	m.Failed = 0
	m.Failures = nil
	tn.SendBackupSummary(m)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	textDry := payload.Text
	mu.Unlock()

	if !strings.Contains(textDry, "[DRY-RUN] NETOPS BACKUP") {
		t.Errorf("expected text to contain '[DRY-RUN] NETOPS BACKUP', got: %s", textDry)
	}

	// Nil notifier should not panic
	var nilTN *TelegramNotifier
	nilTN.SendBackupSummary(m)
}

func TestNewTelegram_ConfigurationAndValidation(t *testing.T) {
	// Disabled
	if tn := NewTelegram(TelegramConfig{Enabled: false, BotToken: "tok", ChatID: "123"}); tn != nil {
		t.Error("expected nil for disabled config")
	}

	// Missing bot token
	if tn := NewTelegram(TelegramConfig{Enabled: true, BotToken: "", ChatID: "123"}); tn != nil {
		t.Error("expected nil for missing BotToken")
	}

	// Missing chat id
	if tn := NewTelegram(TelegramConfig{Enabled: true, BotToken: "tok", ChatID: ""}); tn != nil {
		t.Error("expected nil for missing ChatID")
	}

	// ProxyURL handling
	tnProxy := NewTelegram(TelegramConfig{
		Enabled:  true,
		BotToken: "tok",
		ChatID:   "123",
		ProxyURL: "http://127.0.0.1:8888",
	})
	if tnProxy == nil {
		t.Fatal("expected non-nil for proxy config")
	}
	defer tnProxy.Close()

	tr, ok := tnProxy.client.Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Error("expected custom Proxy transport configured")
	} else {
		req, _ := http.NewRequest(http.MethodGet, "https://api.telegram.org", nil)
		proxyURL, err := tr.Proxy(req)
		if err != nil || proxyURL == nil || proxyURL.Host != "127.0.0.1:8888" {
			t.Errorf("expected proxy host 127.0.0.1:8888, got: %v (err: %v)", proxyURL, err)
		}
	}

	// Close on nil notifier should not panic
	var nilTN *TelegramNotifier
	nilTN.Close()
}

func TestConfigFromResolver_AndEnv(t *testing.T) {
	tests := []struct {
		name       string
		dotEnv     map[string]string
		lookupEnv  map[string]string
		wantEnable bool
		wantThread int
		wantCD     int
		wantSilent bool
	}{
		{
			name: "truthy_strings_in_dotenv",
			dotEnv: map[string]string{
				"TELEGRAM_ENABLED":           "yes",
				"TELEGRAM_BOT_TOKEN":         "tok-1",
				"TELEGRAM_CHAT_ID":           "chat-1",
				"TELEGRAM_MESSAGE_THREAD_ID": "15",
				"TELEGRAM_COOLDOWN_SECONDS":  "45",
				"TELEGRAM_SILENT":            "on",
				"TELEGRAM_PROXY_URL":         "http://proxy:8080",
			},
			wantEnable: true,
			wantThread: 15,
			wantCD:     45,
			wantSilent: true,
		},
		{
			name: "numeric_enabled_and_lookup",
			lookupEnv: map[string]string{
				"TELEGRAM_ENABLED":           "1",
				"TELEGRAM_BOT_TOKEN":         "tok-2",
				"TELEGRAM_CHAT_ID":           "chat-2",
				"TELEGRAM_MESSAGE_THREAD_ID": "invalid",
				"TELEGRAM_COOLDOWN_SECONDS":  "-5",
			},
			wantEnable: true,
			wantThread: 0,
			wantCD:     0,
			wantSilent: false,
		},
		{
			name: "disabled_string",
			dotEnv: map[string]string{
				"TELEGRAM_ENABLED": "false",
			},
			wantEnable: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := &credentials.Resolver{
				DotEnv: tc.dotEnv,
				LookupEnv: func(key string) (string, bool) {
					if tc.lookupEnv != nil {
						v, ok := tc.lookupEnv[key]
						return v, ok
					}
					return "", false
				},
			}

			cfg := ConfigFromResolver(res)
			if cfg.Enabled != tc.wantEnable {
				t.Errorf("Enabled got %v, want %v", cfg.Enabled, tc.wantEnable)
			}
			if tc.wantThread > 0 && cfg.ThreadID != tc.wantThread {
				t.Errorf("ThreadID got %d, want %d", cfg.ThreadID, tc.wantThread)
			}
			if tc.wantCD > 0 && cfg.CooldownSeconds != tc.wantCD {
				t.Errorf("CooldownSeconds got %d, want %d", cfg.CooldownSeconds, tc.wantCD)
			}
			if tc.wantSilent && !cfg.Silent {
				t.Errorf("Silent got %v, want %v", cfg.Silent, tc.wantSilent)
			}
		})
	}

	// Test ConfigFromEnv fallback to process env
	os.Setenv("TELEGRAM_ENABLED", "true")
	os.Setenv("TELEGRAM_BOT_TOKEN", "env-tok")
	os.Setenv("TELEGRAM_CHAT_ID", "env-chat")
	defer func() {
		os.Unsetenv("TELEGRAM_ENABLED")
		os.Unsetenv("TELEGRAM_BOT_TOKEN")
		os.Unsetenv("TELEGRAM_CHAT_ID")
	}()

	envCfg := ConfigFromEnv()
	if !envCfg.Enabled || envCfg.BotToken != "env-tok" || envCfg.ChatID != "env-chat" {
		t.Errorf("unexpected ConfigFromEnv result: %+v", envCfg)
	}
}
