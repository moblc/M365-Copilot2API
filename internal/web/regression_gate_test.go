package web

import (
	"errors"
	"testing"
	"time"

	"m365-copilot2api/internal/chathub"
)

// These assertions encode the three reported production failures. They are
// expected to FAIL against the pre-fix implementation, which is the point:
// a regression gate that never went red proves nothing.
func TestGateProof_TransportCooldownMustGrow(t *testing.T) {
	first := CooldownForCategory(CategoryWSHandshake, 0, 1)
	fifth := CooldownForCategory(CategoryWSHandshake, 0, 5)
	if fifth <= first {
		t.Fatalf("WS_HANDSHAKE cooldown did not escalate: attempt1=%v attempt5=%v", first, fifth)
	}
}

func TestGateProof_SuccessMustNotReopenCircuit(t *testing.T) {
	ResetGlobalCircuit()
	wsErr := &chathub.DialError{Kind: "WS_HANDSHAKE"}
	for i := 0; i < 12; i++ {
		GlobalCircuitRecord(wsErr)
	}
	GlobalCircuitRecord(nil) // upstream answered: transport works again
	if GlobalCircuitIsOpen() {
		t.Fatalf("a success re-opened the circuit until %v", GlobalCircuitOpenUntil())
	}
}

func TestGateProof_EarliestRecoveryMustSeeOpenCircuit(t *testing.T) {
	// newAccountHealth() resets the circuit, so build the pool first and trip
	// the breaker afterwards.
	h := newAccountHealth()
	wsErr := &chathub.DialError{Kind: "WS_HANDSHAKE"}
	for i := 0; i < 12; i++ {
		GlobalCircuitRecord(wsErr)
	}
	if !GlobalCircuitIsOpen() {
		t.Fatal("precondition: circuit should be open")
	}
	if got := h.EarliestRecovery(); got.IsZero() {
		t.Fatal("EarliestRecovery ignored the open circuit and reported nobody cooling")
	}
	_ = errors.Is
	_ = time.Now
}
