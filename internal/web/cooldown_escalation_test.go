package web

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"m365-copilot2api/internal/auth"
	"m365-copilot2api/internal/chathub"
)

// 这些用例锁定线上反馈的四个问题：
//  1. 传输类失败（WS_HANDSHAKE / DNS / TLS ...）的冷却时间永不增长，重试一次
//     就又是一模一样的短窗口，于是账号被反复拉起来打同一堵墙。
//  2. 429 的退避同样随窗口过期被清零。
//  3. 全局熔断把“成功”也算进失败比例里，恢复后仍被继续拦一个窗口。
//  4. 熔断打开时没有任何账号在冷却，EarliestRecovery 返回零值，调用方以为
//     无需等待，于是反复撞向已经打开的熔断。

func wsHandshakeFailure() error {
	return &chathub.DialError{Status: http.StatusBadGateway, Kind: "WS_HANDSHAKE"}
}

func quota429Failure() error {
	return &chathub.DialError{Status: http.StatusTooManyRequests, Kind: "QUOTA_429"}
}

// lapseCooldown 把当前冷却窗口推到过去，模拟“等一会儿再重试”。
// 只挪时间戳，逐出动作交给下一次 cleanupExpiredCooldownLocked。
func lapseCooldown(h *accountHealth, accountID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cooldown[accountID] = time.Now().Add(-time.Second)
}

func cooldownRemaining(h *accountHealth, accountID string) time.Duration {
	until, ok := h.CooldownUntil(accountID)
	if !ok {
		return 0
	}
	return time.Until(until)
}

// 传输类失败按连败次数叠加：15s → 30s → 60s ...，并止步于 transportCooldownMax。
func TestTransportCooldownEscalatesWithStreak(t *testing.T) {
	max := transportCooldownMax()
	var prev time.Duration
	for attempt := 1; attempt <= 6; attempt++ {
		got := CooldownForCategory(CategoryWSHandshake, 0, attempt)
		if got <= 0 {
			t.Fatalf("attempt %d: cooldown must be positive, got %v", attempt, got)
		}
		if got > max {
			t.Fatalf("attempt %d: cooldown %v exceeds transport cap %v", attempt, got, max)
		}
		if attempt > 1 && got <= prev {
			t.Fatalf("attempt %d: cooldown %v did not grow past %v", attempt, got, prev)
		}
		prev = got
	}
	if base := CooldownForCategory(CategoryWSHandshake, 0, 1); base != 15*time.Second {
		t.Fatalf("first transport failure should cool for 15s, got %v", base)
	}
	if last := CooldownForCategory(CategoryWSHandshake, 0, 99); last != max {
		t.Fatalf("a long streak must stop at the transport cap %v, got %v", max, last)
	}
}

// 核心回归：窗口过期后连败次数不能被清零，否则冷却永远停在基础值。
func TestTransportCooldownKeepsGrowingAfterWindowLapses(t *testing.T) {
	h := newAccountHealth()
	const acc = "u-transport"

	h.MarkFailure(acc, wsHandshakeFailure(), 60*time.Second)
	first := cooldownRemaining(h, acc)
	if first < 10*time.Second {
		t.Fatalf("first transport failure cooled for %v, want ~15s", first)
	}

	lapseCooldown(h, acc)
	if !h.Available(acc) {
		t.Fatal("an expired cooldown must make the account available again")
	}

	h.MarkFailure(acc, wsHandshakeFailure(), 60*time.Second)
	second := cooldownRemaining(h, acc)
	if second <= first {
		t.Fatalf("a repeated transport failure must cool longer: first=%v second=%v", first, second)
	}

	lapseCooldown(h, acc)
	h.MarkFailure(acc, wsHandshakeFailure(), 60*time.Second)
	third := cooldownRemaining(h, acc)
	if third <= second {
		t.Fatalf("the cooldown must keep growing across lapsed windows: second=%v third=%v", second, third)
	}
	if h.FailStreak(acc) != 3 {
		t.Fatalf("consecutive failures should be tracked, got streak %d", h.FailStreak(acc))
	}
}

// 429 同样要在窗口过期后继续增长，而不是每次回到 15s。
func TestQuota429CooldownKeepsGrowingAfterWindowLapses(t *testing.T) {
	h := newAccountHealth()
	const acc = "u-quota"

	h.MarkFailure(acc, quota429Failure(), 60*time.Second)
	first := cooldownRemaining(h, acc)
	if first < 10*time.Second {
		t.Fatalf("first 429 cooled for %v, want ~15s", first)
	}

	lapseCooldown(h, acc)
	h.MarkFailure(acc, quota429Failure(), 60*time.Second)
	second := cooldownRemaining(h, acc)
	if second <= first {
		t.Fatalf("a repeated 429 must cool longer: first=%v second=%v", first, second)
	}

	// 上游给出 Retry-After 时以上游为准，但仍不得短于基础窗口。
	lapseCooldown(h, acc)
	if d := CooldownForCategory(CategoryQuota429, 120, 4); d != 120*time.Second {
		t.Fatalf("Retry-After must win: want 120s, got %v", d)
	}
}

// 成功是唯一能证明账号恢复的信号，必须把连败计数清零。
func TestSuccessResetsCooldownEscalation(t *testing.T) {
	h := newAccountHealth()
	const acc = "u-recover"

	for i := 0; i < 3; i++ {
		h.MarkFailure(acc, wsHandshakeFailure(), 60*time.Second)
		lapseCooldown(h, acc)
	}
	if h.FailStreak(acc) != 3 {
		t.Fatalf("want streak 3 before recovery, got %d", h.FailStreak(acc))
	}

	h.MarkSuccess(acc)
	if got := h.FailStreak(acc); got != 0 {
		t.Fatalf("a success must reset the escalation streak, got %d", got)
	}

	h.MarkFailure(acc, wsHandshakeFailure(), 60*time.Second)
	if got := cooldownRemaining(h, acc); got > 20*time.Second {
		t.Fatalf("after a success the next failure must use the base window, got %v", got)
	}
}

// 成功不能被算进失败比例：否则上游已经恢复，熔断仍会被“重新武装”一个窗口。
func TestGlobalCircuitSuccessClearsFailureBurst(t *testing.T) {
	ResetGlobalCircuit()
	t.Cleanup(ResetGlobalCircuit)

	for i := 0; i < globalCircuitMinFails-3; i++ {
		GlobalCircuitRecord(wsHandshakeFailure())
	}
	GlobalCircuitRecord(nil) // 上游恢复，链路已经通了
	for i := 0; i < 3; i++ {
		GlobalCircuitRecord(wsHandshakeFailure())
	}
	if GlobalCircuitIsOpen() {
		t.Fatal("a successful round trip must reset the failure burst instead of counting towards tripping the circuit")
	}
	if GlobalCircuitIsOpen() || GlobalCircuitTrips() != 0 {
		t.Fatalf("circuit should never have tripped, trips=%d", GlobalCircuitTrips())
	}
}

// 连续多次熔断，打开的窗口必须越来越长。
func TestGlobalCircuitOpenEscalatesPerTrip(t *testing.T) {
	ResetGlobalCircuit()
	t.Cleanup(ResetGlobalCircuit)

	for i := 0; i < globalCircuitMinFails; i++ {
		GlobalCircuitRecord(wsHandshakeFailure())
	}
	if !GlobalCircuitIsOpen() {
		t.Fatalf("a burst of %d transport failures must open the circuit", globalCircuitMinFails)
	}
	first := time.Until(GlobalCircuitOpenUntil())

	// 让窗口过期，再来一轮同样的爆发。
	globalCircuit.mu.Lock()
	globalCircuit.openUntil = time.Now().Add(-time.Second)
	globalCircuit.mu.Unlock()
	if GlobalCircuitIsOpen() {
		t.Fatal("circuit should report closed once its window expired")
	}
	for i := 0; i < globalCircuitMinFails; i++ {
		GlobalCircuitRecord(wsHandshakeFailure())
	}
	second := time.Until(GlobalCircuitOpenUntil())
	if !GlobalCircuitIsOpen() {
		t.Fatal("the second burst must trip the circuit again")
	}
	if second <= first {
		t.Fatalf("each consecutive trip must stay open longer: first=%v second=%v", first, second)
	}
	if GlobalCircuitTrips() != 2 {
		t.Fatalf("want 2 trips, got %d", GlobalCircuitTrips())
	}
}

// 熔断打开时没有任何账号在冷却，EarliestRecovery 也必须给出等待时间。
func TestEarliestRecoveryIncludesOpenCircuit(t *testing.T) {
	ResetGlobalCircuit()
	t.Cleanup(ResetGlobalCircuit)

	h := newAccountHealth()
	if got := h.EarliestRecovery(); !got.IsZero() {
		t.Fatalf("nothing cooling or tripped should report no recovery time, got %v", got)
	}

	for i := 0; i < globalCircuitMinFails; i++ {
		GlobalCircuitRecord(wsHandshakeFailure())
	}
	if got := h.EarliestRecovery(); got.IsZero() {
		t.Fatal("an open circuit gates every account and must be part of the earliest recovery time")
	}
}

// 熔断打开时应快速失败并给出可用的 Retry-After，而不是排队等到超时。
func TestResolveAccountFailsFastWhenCircuitOpen(t *testing.T) {
	ResetGlobalCircuit()
	t.Cleanup(ResetGlobalCircuit)

	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := auth.OpenStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	live := auth.TokenSet{
		HomeOID:      "u-live",
		Email:        "live@example.com",
		AccessToken:  "tok-live",
		RefreshToken: "r-live",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if _, err := store.Upsert(live); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	s := &Server{tokens: store, accountPool: newAccountHealth(), accountConcurrency: newAccountConcurrency()}

	// 账号本身完全健康，共享传输层在坏。
	for i := 0; i < globalCircuitMinFails; i++ {
		GlobalCircuitRecord(wsHandshakeFailure())
	}

	start := time.Now()
	_, resolveErr := s.resolveAccountCtx(context.Background(), "")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("an open circuit must fail fast, waited %v", elapsed)
	}
	var upstream *UpstreamHTTPError
	if !errors.As(resolveErr, &upstream) {
		t.Fatalf("want *UpstreamHTTPError, got %v", resolveErr)
	}
	if upstream.Status != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%q", upstream.Status, upstream.Body)
	}
	if upstream.ErrorCode != "transport_error" {
		t.Fatalf("error code=%q, want transport_error", upstream.ErrorCode)
	}
	if upstream.RetryAfter <= 0 {
		t.Fatalf("Retry-After must tell the client when to come back, got %d", upstream.RetryAfter)
	}
}

// 耗尽所有账号时要说明真实原因：传输故障不能伪装成 429 限流。
func TestFailoverExhaustedNamesTheRealReason(t *testing.T) {
	ResetGlobalCircuit()
	t.Cleanup(ResetGlobalCircuit)

	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := auth.OpenStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	live := auth.TokenSet{HomeOID: "u-only", Email: "only@example.com", AccessToken: "tok", RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := store.Upsert(live); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	s := &Server{tokens: store, accountPool: newAccountHealth(), accountConcurrency: newAccountConcurrency()}

	// 传输层故障：503 + transport_error，客户端才能正确区分。
	s.accountPool.MarkFailure("u-only", wsHandshakeFailure(), 60*time.Second)
	status, retry, payload := s.failoverExhaustedDetails(nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("transport exhaustion should answer 503, got %d", status)
	}
	if retry <= 0 {
		t.Fatalf("Retry-After should be positive, got %d", retry)
	}
	body := payload["error"].(map[string]any)
	if body["type"] != "transport_error" {
		t.Fatalf("error type=%v, want transport_error", body["type"])
	}

	// 真正的配额耗尽仍保持 429。
	ResetGlobalCircuit()
	h := newAccountHealth()
	s.accountPool = h
	h.MarkFailure("u-only", quota429Failure(), 60*time.Second)
	status, _, payload = s.failoverExhaustedDetails(nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("quota exhaustion should stay 429, got %d", status)
	}
	body = payload["error"].(map[string]any)
	if body["type"] != "rate_limit_error" {
		t.Fatalf("error type=%v, want rate_limit_error", body["type"])
	}
}
