package chathub

import (
	"testing"
	"time"
)

// A pooled socket is bound upstream to the IDs in its own URL. Take must hand
// those IDs to the consuming request, must hand a socket out at most once, and
// must not give a socket dialed for one scenario/license to another.
func TestPoolTakeIsSingleUseAndCarriesItsIDs(t *testing.T) {
	p := &ConnPool{conns: map[string][]*pooledConn{}}
	ids := PooledIDs{SessionID: "sess-warm", ConversationID: "conv-warm", RequestID: "req-warm"}
	p.conns[p.key("oid", "tid")] = []*pooledConn{{
		created: time.Now(), handshook: true, ids: ids,
		variant: poolVariant("Starter", "OfficeWebIncludedCopilot"),
	}}

	if _, _, ok := p.Take("oid", "tid", "Premium", "OfficeWebPaidCopilot"); ok {
		t.Fatal("socket dialed for another scenario/license must not be handed out")
	}
	if _, _, ok := p.Take("other-oid", "tid", "Starter", "OfficeWebIncludedCopilot"); ok {
		t.Fatal("socket of another account must not be handed out")
	}
	_, got, ok := p.Take("oid", "tid", "Starter", "OfficeWebIncludedCopilot")
	if !ok {
		t.Fatal("matching warm socket should be handed out")
	}
	if got != ids {
		t.Fatalf("request must adopt the socket's own IDs, got %+v want %+v", got, ids)
	}
	if _, _, ok := p.Take("oid", "tid", "Starter", "OfficeWebIncludedCopilot"); ok {
		t.Fatal("a socket must never be handed out twice")
	}
	if n := p.Idle("oid", "tid"); n != 0 {
		t.Fatalf("pool should be empty after the only socket was taken, idle=%d", n)
	}
}

func TestMemoryDisabledRequestsAreNotPoolEligible(t *testing.T) {
	if poolEligibleFor(Request{DisableMemory: true}) {
		t.Fatal("memory-disabled request needs its own URL flag and must dial")
	}
}
