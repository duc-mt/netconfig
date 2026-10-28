// ==============================================================================
// File name:     cve_test.go
// Description:   Tests of the Telegram CVE alert: rendering, splitting,
//                delivery against a mock Bot API and token redaction.
// License:       MIT
// ==============================================================================

package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"netops/internal/cve"
)

func adv(id string, sev cve.Severity, cvss float64, fixed string) cve.Advisory {
	return cve.Advisory{ID: id, Severity: sev, CVSS: cvss, FixedVer: fixed}
}

func router01() cve.DeviceCVEResult {
	return cve.DeviceCVEResult{
		Hostname: "router-01", IP: "10.0.0.1", Vendor: "cisco", OS: "cisco-ios-xe", Version: "17.6.1",
		Advisories: []cve.Advisory{
			adv("CVE-2023-20198", cve.SeverityCritical, 10.0, "17.6.2"),
			adv("CVE-2023-20273", cve.SeverityCritical, 9.1, "17.6.2"),
			adv("CVE-2021-1234", cve.SeverityHigh, 7.5, ""),
		},
	}
}

func TestFormatCVEAlertMatchesTheSpecifiedLayout(t *testing.T) {
	got := FormatCVEAlert([]cve.DeviceCVEResult{router01()})
	want := "🚨 <b>NetOps CVE Alert Summary</b>\n" +
		"Found <b>3</b> vulnerabilities across <b>1</b> device:\n" +
		"• <b>router-01</b> (cisco-ios-xe 17.6.1): <b>2 Critical</b>, <b>1 High</b>\n" +
		"  - <code>CVE-2023-20198</code> (CVSS 10.0) [Fixed: 17.6.2]\n" +
		"  - <code>CVE-2023-20273</code> (CVSS 9.1) [Fixed: 17.6.2]\n" +
		"  - <code>CVE-2021-1234</code> (CVSS 7.5) [Fixed: unknown]"
	if len(got) != 1 || got[0] != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestFormatCVEAlertNothingToReport(t *testing.T) {
	if got := FormatCVEAlert(nil); got != nil {
		t.Errorf("nil results: %q", got)
	}
	clean := cve.DeviceCVEResult{Hostname: "ok", Advisories: []cve.Advisory{}}
	failed := cve.DeviceCVEResult{Hostname: "bad", Error: "no advisory data"}
	if got := FormatCVEAlert([]cve.DeviceCVEResult{clean, failed}); got != nil {
		t.Errorf("clean and unchecked devices are not alerts: %q", got)
	}
}

func TestFormatCVEAlertCountsAcrossDevicesAndSkipsCleanOnes(t *testing.T) {
	r2 := cve.DeviceCVEResult{Hostname: "fw-01", OS: "fortios", Version: "v7.2.4", Advisories: []cve.Advisory{adv("CVE-2023-27997", cve.SeverityCritical, 9.8, "7.2.5")}}
	clean := cve.DeviceCVEResult{Hostname: "sw-9", Advisories: []cve.Advisory{}}
	got := FormatCVEAlert([]cve.DeviceCVEResult{router01(), clean, r2})
	if len(got) != 1 {
		t.Fatalf("messages = %d", len(got))
	}
	for _, want := range []string{"Found <b>4</b> vulnerabilities across <b>2</b> devices:", "• <b>fw-01</b> (fortios v7.2.4): <b>1 Critical</b>"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("missing %q in:\n%s", want, got[0])
		}
	}
	if strings.Contains(got[0], "sw-9") {
		t.Error("a clean device must not appear")
	}
}

func TestFormatCVEAlertSingularsAndSeverityLabels(t *testing.T) {
	r := cve.DeviceCVEResult{Hostname: "h", OS: "junos", Version: "21.2R3", Advisories: []cve.Advisory{
		adv("CVE-1", cve.SeverityMedium, 5.5, "x"), adv("CVE-2", cve.SeverityLow, 2.0, "x"),
		adv("CVE-3", cve.SeverityUnknown, 0, ""),
	}}
	got := FormatCVEAlert([]cve.DeviceCVEResult{r})[0]
	for _, want := range []string{"<b>1 Medium</b>, <b>1 Low</b>, <b>1 Unscored</b>", "(CVSS n/a) [Fixed: unknown]"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	one := FormatCVEAlert([]cve.DeviceCVEResult{{Hostname: "h", Advisories: []cve.Advisory{adv("CVE-1", cve.SeverityHigh, 8, "")}}})[0]
	if !strings.Contains(one, "Found <b>1</b> vulnerability across <b>1</b> device:") {
		t.Errorf("singular forms: %s", one)
	}
	// a severity this code does not know is still counted
	odd := FormatCVEAlert([]cve.DeviceCVEResult{{Hostname: "h", Advisories: []cve.Advisory{{ID: "CVE-9", Severity: "WEIRD"}}}})[0]
	if !strings.Contains(odd, "<b>1 Unscored</b>") {
		t.Errorf("unknown severity: %s", odd)
	}
}

func TestFormatCVEAlertEscapesHTMLAndClipsLongFields(t *testing.T) {
	r := cve.DeviceCVEResult{
		Hostname: `evil<script>&"x"`, OS: "os<b>", Version: "1.0&2",
		Advisories: []cve.Advisory{adv("CVE-<1>", cve.SeverityHigh, 7.5, "fix<>"), adv("CVE-2", cve.SeverityHigh, 7.1, strings.Repeat("9.9.9, ", 40))},
	}
	got := FormatCVEAlert([]cve.DeviceCVEResult{r})[0]
	for _, bad := range []string{"<script>", "<b>os", "&2", "CVE-<1>", "fix<>"} {
		if strings.Contains(got, bad) {
			t.Errorf("unescaped %q in:\n%s", bad, got)
		}
	}
	for _, want := range []string{"evil&lt;script&gt;&amp;&#34;x&#34;", "os&lt;b&gt;", "1.0&amp;2", "CVE-&lt;1&gt;", "[Fixed: fix&lt;&gt;]"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Count(got, "9.9.9") > 10 || !strings.Contains(got, "…") {
		t.Errorf("an absurdly long fixed-version list must be clipped:\n%s", got)
	}
}

func TestFormatCVEAlertDeviceNameFallbacks(t *testing.T) {
	a := []cve.Advisory{adv("CVE-1", cve.SeverityHigh, 8, "")}
	for name, tc := range map[string]struct {
		r    cve.DeviceCVEResult
		want string
	}{
		"hostname": {cve.DeviceCVEResult{Hostname: "h1", IP: "10.0.0.1", Advisories: a}, "<b>h1</b>"},
		"ip":       {cve.DeviceCVEResult{IP: "10.0.0.1", Advisories: a}, "<b>10.0.0.1</b>"},
		"ad hoc":   {cve.DeviceCVEResult{OS: "junos", Version: "21.2R3", Advisories: a}, "<b>(unnamed)</b> (junos 21.2R3)"},
	} {
		if got := FormatCVEAlert([]cve.DeviceCVEResult{tc.r})[0]; !strings.Contains(got, tc.want) {
			t.Errorf("%s: %s", name, got)
		}
	}
}

func TestFormatCVEAlertListsAtMostFiveAdvisoriesPerDevice(t *testing.T) {
	var advs []cve.Advisory
	for i := 0; i < 8; i++ {
		advs = append(advs, adv(fmt.Sprintf("CVE-2024-%04d", i), cve.SeverityHigh, 8.0, "1.2"))
	}
	got := FormatCVEAlert([]cve.DeviceCVEResult{{Hostname: "big", OS: "eos", Version: "4.28.3M", Advisories: advs}})[0]
	if strings.Count(got, "  - <code>") != 5 || !strings.Contains(got, "  … and 3 more") {
		t.Errorf("per-device cap:\n%s", got)
	}
	if !strings.Contains(got, "Found <b>8</b> vulnerabilities") || !strings.Contains(got, "<b>8 High</b>") {
		t.Errorf("the counts still include every advisory:\n%s", got)
	}
}

func manyDevices(n int) []cve.DeviceCVEResult {
	out := make([]cve.DeviceCVEResult, n)
	for i := range out {
		out[i] = cve.DeviceCVEResult{
			Hostname: fmt.Sprintf("core-router-%03d.example.net", i), OS: "cisco-ios-xe", Version: "17.6.1",
			Advisories: []cve.Advisory{
				adv("CVE-2023-20198", cve.SeverityCritical, 10, "17.6.6a"), adv("CVE-2023-20273", cve.SeverityCritical, 9.1, "17.6.6a"),
				adv("CVE-2022-20000", cve.SeverityHigh, 8.1, "17.6.4"), adv("CVE-2022-20001", cve.SeverityHigh, 7.7, "17.6.4"),
				adv("CVE-2021-20002", cve.SeverityMedium, 5.5, "17.6.3"),
			},
		}
	}
	return out
}

func TestFormatCVEAlertSplitsLongAlertsUnderTelegramsLimit(t *testing.T) {
	res := manyDevices(20)
	msgs := FormatCVEAlert(res)
	if len(msgs) < 2 {
		t.Fatalf("20 devices should not fit one message, got %d", len(msgs))
	}
	seen := 0
	for i, m := range msgs {
		if n := utf8.RuneCountInString(m); n > 4096 {
			t.Errorf("message %d has %d characters, above Telegram's 4096", i+1, n)
		}
		if i == 0 && !strings.HasPrefix(m, "🚨 <b>NetOps CVE Alert Summary</b>\nFound <b>100</b> vulnerabilities across <b>20</b> devices:") {
			t.Errorf("the summary belongs in the first message only:\n%s", m[:120])
		}
		if i > 0 && !strings.HasPrefix(m, "🚨 <b>NetOps CVE Alert</b> (continued)\n") {
			t.Errorf("message %d lacks the continuation header", i+1)
		}
		seen += strings.Count(m, "• <b>")
		// tags stay balanced: no message is cut in the middle of a block
		for _, tag := range []string{"b", "code"} {
			if strings.Count(m, "<"+tag+">") != strings.Count(m, "</"+tag+">") {
				t.Errorf("message %d has unbalanced <%s> tags", i+1, tag)
			}
		}
	}
	if seen != 20 {
		t.Errorf("%d device blocks across the messages, want 20", seen)
	}
}

func TestFormatCVEAlertCutsOffAfterFourMessages(t *testing.T) {
	msgs := FormatCVEAlert(manyDevices(200))
	if len(msgs) != cveMaxMessages {
		t.Fatalf("messages = %d, want the cap of %d", len(msgs), cveMaxMessages)
	}
	last := msgs[len(msgs)-1]
	if !strings.Contains(last, "more devices not shown; see the CSV/JSON report.") {
		t.Errorf("the truncation must be announced:\n%s", last[len(last)-200:])
	}
	shown := 0
	for _, m := range msgs {
		if utf8.RuneCountInString(m) > 4096 {
			t.Error("a message exceeds Telegram's limit")
		}
		shown += strings.Count(m, "• <b>")
	}
	var dropped int
	if _, err := fmt.Sscanf(last[strings.LastIndex(last, "<i>… ")+len("<i>… "):], "%d more", &dropped); err != nil || shown+dropped != 200 {
		t.Errorf("shown %d + announced %d must account for all 200 devices (err %v)", shown, dropped, err)
	}
	// the singular form
	exactly := FormatCVEAlert(manyDevices(0))
	if exactly != nil {
		t.Error("no devices, no alert")
	}
}

// ---- delivery -------------------------------------------------------------------------------

type fakeBot struct {
	srv      *httptest.Server
	mu       sync.Mutex
	payloads []telegramPayload
	status   int
}

func newFakeBot(t *testing.T) *fakeBot {
	t.Helper()
	b := &fakeBot{status: http.StatusOK}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if !strings.HasSuffix(r.URL.Path, "/sendMessage") {
			http.NotFound(w, r)
			return
		}
		var p telegramPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		b.payloads = append(b.payloads, p)
		w.WriteHeader(b.status)
		if b.status == http.StatusOK {
			_, _ = w.Write([]byte(`{"ok":true}`))
		} else {
			_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: can't parse entities"}`))
		}
	}))
	t.Cleanup(b.srv.Close)
	old := newTelegram
	newTelegram = func(cfg TelegramConfig) *TelegramNotifier {
		tn := NewTelegram(cfg)
		if tn != nil {
			tn.SetBaseURL(b.srv.URL + "/bot" + cfg.BotToken) // the real API URL carries the token
		}
		return tn
	}
	t.Cleanup(func() { newTelegram = old })
	oldGap := cveMessageGap
	cveMessageGap = time.Millisecond
	t.Cleanup(func() { cveMessageGap = oldGap })
	return b
}

var goodCfg = TelegramConfig{Enabled: true, BotToken: "123456:SECRET-TOKEN", ChatID: "-100777", ThreadID: 5, Silent: true}

func TestSendCVEAlertDeliversEveryMessageInOrder(t *testing.T) {
	bot := newFakeBot(t)
	res := manyDevices(20)
	want := FormatCVEAlert(res)
	if err := SendCVEAlert(context.Background(), goodCfg, res); err != nil {
		t.Fatal(err)
	}
	if len(bot.payloads) != len(want) {
		t.Fatalf("sent %d messages, want %d", len(bot.payloads), len(want))
	}
	for i, p := range bot.payloads {
		if p.Text != want[i] || p.ParseMode != "HTML" || p.ChatID != "-100777" || p.MessageThreadID != 5 || !p.DisableNotification || !p.DisableWebPagePreview {
			t.Errorf("payload %d = %+v", i, p)
		}
	}
}

func TestSendCVEAlertWithNothingToReportSendsNothing(t *testing.T) {
	bot := newFakeBot(t)
	// even with Telegram unconfigured: there is nothing to deliver, so nothing can fail
	for _, cfg := range []TelegramConfig{goodCfg, {}} {
		if err := SendCVEAlert(context.Background(), cfg, []cve.DeviceCVEResult{{Hostname: "ok"}}); err != nil {
			t.Errorf("err = %v", err)
		}
	}
	if len(bot.payloads) != 0 {
		t.Errorf("sent %d messages", len(bot.payloads))
	}
}

func TestSendRequiresAConfiguredTelegram(t *testing.T) {
	newFakeBot(t)
	for name, cfg := range map[string]TelegramConfig{
		"disabled": {Enabled: false, BotToken: "t", ChatID: "c"},
		"no token": {Enabled: true, ChatID: "c"},
		"no chat":  {Enabled: true, BotToken: "t"},
	} {
		if err := SendCVEAlert(context.Background(), cfg, []cve.DeviceCVEResult{router01()}); !errors.Is(err, ErrTelegramNotConfigured) {
			t.Errorf("%s: SendCVEAlert err = %v", name, err)
		}
		if err := SendTelegram(context.Background(), cfg, "hi"); !errors.Is(err, ErrTelegramNotConfigured) {
			t.Errorf("%s: SendTelegram err = %v", name, err)
		}
	}
}

func TestSendTelegramSendsOneMessage(t *testing.T) {
	bot := newFakeBot(t)
	if err := SendTelegram(context.Background(), goodCfg, "<b>hello</b>"); err != nil {
		t.Fatal(err)
	}
	if len(bot.payloads) != 1 || bot.payloads[0].Text != "<b>hello</b>" {
		t.Errorf("payloads = %+v", bot.payloads)
	}
}

func TestSendReportsAPIErrorsAndWhichMessageFailed(t *testing.T) {
	bot := newFakeBot(t)
	bot.status = http.StatusBadRequest
	err := SendCVEAlert(context.Background(), goodCfg, manyDevices(20))
	if err == nil || !strings.Contains(err.Error(), "message 1 of") || !strings.Contains(err.Error(), "telegram api error 400") || !strings.Contains(err.Error(), "can't parse entities") {
		t.Errorf("err = %v", err)
	}
	if len(bot.payloads) != 1 {
		t.Errorf("a failure must stop the remaining messages, sent %d", len(bot.payloads))
	}
	// a single-message alert carries no "message 1 of 1" noise
	bot2 := newFakeBot(t)
	bot2.status = http.StatusBadRequest
	err = SendCVEAlert(context.Background(), goodCfg, []cve.DeviceCVEResult{router01()})
	if err == nil || strings.Contains(err.Error(), "message 1 of") {
		t.Errorf("err = %v", err)
	}
}

func TestSendNeverLeaksTheBotTokenInErrors(t *testing.T) {
	bot := newFakeBot(t)
	bot.srv.Close() // connection refused: net/http puts the full URL, token included, in the error
	err := SendCVEAlert(context.Background(), goodCfg, []cve.DeviceCVEResult{router01()})
	if err == nil {
		t.Fatal("expected a delivery error")
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Errorf("the bot token leaked into the error: %v", err)
	}
	if !strings.Contains(err.Error(), "***") {
		t.Errorf("the redaction should be visible: %v", err)
	}
	if err := SendTelegram(context.Background(), goodCfg, "x"); err == nil || strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Errorf("SendTelegram leaked or succeeded: %v", err)
	}
}

func TestRedactToken(t *testing.T) {
	e := errors.New("plain")
	if got := redactToken(e, "tok"); got != e {
		t.Error("an error without the token is returned unchanged")
	}
	if got := redactToken(e, ""); got != e {
		t.Error("an empty token redacts nothing")
	}
	if got := redactToken(errors.New("POST https://api.telegram.org/bottok123/sendMessage: boom"), "tok123"); strings.Contains(got.Error(), "tok123") || !strings.Contains(got.Error(), "bot***/sendMessage") {
		t.Errorf("got %v", got)
	}
}

func TestSendStopsBetweenMessagesWhenCancelled(t *testing.T) {
	bot := newFakeBot(t)
	cveMessageGap = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := SendCVEAlert(ctx, goodCfg, manyDevices(20))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second || len(bot.payloads) != 1 {
		t.Errorf("took %v, sent %d", time.Since(start), len(bot.payloads))
	}
}
