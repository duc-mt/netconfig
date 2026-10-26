package notifier

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
	if payload.Text != "hello netops" {
		t.Errorf("expected text 'hello netops', got %s", payload.Text)
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
		Duration:  5 * time.Second,
		ByCategory: map[task.Category][]string{
			task.CatConnectFailed: {"SW-CORE"},
		},
	}

	tn.SendTaskSummary("config", sum, false)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(payload.Text, "NETOPS CONFIG") {
		t.Errorf("expected payload to contain 'NETOPS CONFIG', got: %s", payload.Text)
	}
	if !strings.Contains(payload.Text, "SW-CORE") {
		t.Errorf("expected payload to contain 'SW-CORE', got: %s", payload.Text)
	}
}
