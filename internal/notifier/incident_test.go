// ==============================================================================
// File name:     incident_test.go
// Description:   Tests for the "netops log" Telegram alerts: delivery fields,
//                incident throttling, health alerts and the log-aware config.
// License:       MIT
// ==============================================================================

package notifier

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/internal/credentials"
	"netops/internal/log/collector"
)

func TestLogTelegramNotifier_SendSync(t *testing.T) {
	var received telegramPayload
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/sendMessage") {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true, "result": {"message_id": 123}}`))
	}))
	defer srv.Close()

	cfg := TelegramConfig{
		Enabled:         true,
		BotToken:        "123456:dummy",
		ChatID:          "-100111222333",
		ThreadID:        42,
		CooldownSeconds: 60,
	}

	tn := NewTelegramWithLogger(cfg, nil)
	if tn == nil {
		t.Fatal("expected non-nil notifier")
	}
	defer tn.Close()

	tn.SetBaseURL(srv.URL)

	err := tn.SendSync(t.Context(), "Test message")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if received.ChatID != "-100111222333" {
		t.Errorf("expected chat_id -100111222333, got %s", received.ChatID)
	}
	if received.MessageThreadID != 42 {
		t.Errorf("expected thread_id 42, got %d", received.MessageThreadID)
	}
	if received.Text != "Test message" {
		t.Errorf("expected text 'Test message', got %q", received.Text)
	}
}

func TestLogTelegramNotifier_OnIncident_Throttling(t *testing.T) {
	sentCount := 0
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sentCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	cfg := TelegramConfig{
		Enabled:         true,
		BotToken:        "123456:dummy",
		ChatID:          "-100111222333",
		CooldownSeconds: 300,
	}

	tn := NewTelegramWithLogger(cfg, nil)
	tn.SetBaseURL(srv.URL)
	defer tn.Close()

	rep := collector.IncidentReport{
		ID:       "inc-001",
		Hostname: "CORE-RT-01",
		TriggerLog: collector.LogEntry{
			Event:  "OSPF_DOWN",
			Object: "GigabitEthernet0/0/1",
		},
		Playbook: "ospf_adj_down",
		Diagnostics: []collector.DiagCmd{
			{Command: "show ip ospf neighbor", Output: "neighbor dead", DurationMs: 120},
		},
		TriageHints: []string{"Check MTU and link"},
	}

	// First call should queue
	tn.OnIncident(rep, "/path/inc-001.json")
	// Second call should be throttled by cooldown
	tn.OnIncident(rep, "/path/inc-001.json")

	// Allow worker to process
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	count := sentCount
	mu.Unlock()

	if count != 1 {
		t.Fatalf("expected exactly 1 alert sent due to cooldown, got %d", count)
	}
}

func TestLogTelegramHealthAndCustomAlerts(t *testing.T) {
	var mu sync.Mutex
	var texts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p telegramPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		mu.Lock()
		texts = append(texts, p.Text)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	tn := NewTelegramWithLogger(TelegramConfig{Enabled: true, BotToken: "123456:dummy", ChatID: "-1", CooldownSeconds: 300}, nil)
	tn.SetBaseURL(srv.URL)

	tn.SendDeviceHealth("sw1", false, "i/o timeout")
	tn.SendDeviceHealth("sw1", false, "i/o timeout") // throttled
	tn.SendDeviceHealth("sw1", true, "")
	tn.SendCustomNotification("Heads <up>", "body")
	tn.Close() // flushes the queue

	mu.Lock()
	defer mu.Unlock()
	if len(texts) != 3 {
		t.Fatalf("want 3 messages (failure, recovery, custom), got %d: %q", len(texts), texts)
	}
	if !strings.Contains(texts[0], "NETOPS LOG ALERT") || !strings.Contains(texts[0], "i/o timeout") {
		t.Errorf("failure alert = %q", texts[0])
	}
	if !strings.Contains(texts[1], "NETOPS LOG RECOVERED") {
		t.Errorf("recovery alert = %q", texts[1])
	}
	if !strings.Contains(texts[2], "Heads &lt;up&gt;") {
		t.Errorf("custom title must be HTML-escaped: %q", texts[2])
	}
}

func TestLogTelegramNilNotifierIsSafe(t *testing.T) {
	var tn *TelegramNotifier
	tn.OnIncident(collector.IncidentReport{}, "")
	tn.SendDeviceHealth("sw1", false, "x")
	tn.SendCustomNotification("t", "b")
	tn.Close()
}

func TestConfigForLogDefaultsAndOverrides(t *testing.T) {
	env := map[string]string{"TELEGRAM_ENABLED": "true", "TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "1"}
	r := &credentials.Resolver{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}
	t.Setenv("TELEGRAM_COOLDOWN_SECONDS", "")
	t.Setenv("TELEGRAM_MIN_SEVERITY", "")

	cfg := ConfigForLog(r)
	if !cfg.Enabled || cfg.CooldownSeconds != DefaultLogCooldownSeconds || cfg.MinSeverity != DefaultLogMinSeverity {
		t.Errorf("defaults: %+v", cfg)
	}
	// The shared loader keeps its own (unthrottled) default.
	if got := ConfigFromResolver(r).CooldownSeconds; got != 0 {
		t.Errorf("ConfigFromResolver cooldown = %d, want 0", got)
	}

	env["TELEGRAM_COOLDOWN_SECONDS"] = "45"
	env["TELEGRAM_MIN_SEVERITY"] = " CRITICAL "
	if cfg := ConfigForLog(r); cfg.CooldownSeconds != 45 || cfg.MinSeverity != "critical" {
		t.Errorf("overrides: %+v", cfg)
	}
	env["TELEGRAM_COOLDOWN_SECONDS"] = "bogus"
	if cfg := ConfigForLog(r); cfg.CooldownSeconds != DefaultLogCooldownSeconds {
		t.Errorf("invalid cooldown must fall back to the default, got %d", cfg.CooldownSeconds)
	}
}
