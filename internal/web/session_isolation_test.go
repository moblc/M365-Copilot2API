package web

import "testing"

// Two end users multiplexed behind one API key and one relay IP/UA, told apart
// only by the `user` field, must never resolve onto each other's upstream
// conversation even when their message prefix is identical.
func TestContentKeyDoesNotCrossUserField(t *testing.T) {
	sr := newTenantResolver(t)
	msgs := []oaiMsg{{Role: "user", Content: "hi"}, {Role: "assistant", Content: "Hello!"}}

	sr.Bind("", "conv-alice", "acc-1", &oaiReq{User: "alice", Messages: msgs}, "",
		tenantReq("shared-key", "203.0.113.9", "relay-ua"))

	next := append(append([]oaiMsg{}, msgs...), oaiMsg{Role: "user", Content: "more"})

	res := sr.Resolve(tenantReq("shared-key", "203.0.113.9", "relay-ua"), &oaiReq{User: "bob", Messages: next})
	if !res.IsNew {
		t.Fatalf("user bob reused user alice's conversation %q (matched %q)", res.ConversationID, res.MatchedBy)
	}
	res = sr.Resolve(tenantReq("shared-key", "203.0.113.9", "relay-ua"), &oaiReq{Messages: next})
	if !res.IsNew {
		t.Fatalf("anonymous caller reused user alice's conversation %q", res.ConversationID)
	}
	res = sr.Resolve(tenantReq("shared-key", "203.0.113.9", "relay-ua"), &oaiReq{User: "alice", Messages: next})
	if res.IsNew || res.ConversationID != "conv-alice" {
		t.Fatalf("same-user continuation broken: IsNew=%v conv=%q", res.IsNew, res.ConversationID)
	}
}

// The same `user` value does not by itself continue a conversation: a second,
// unrelated chat from that user must start a new upstream conversation instead
// of being poured into the first one.
func TestSameUserFieldUnrelatedChatIsNew(t *testing.T) {
	sr := newTenantResolver(t)
	sr.Bind("", "conv-1", "acc-1", &oaiReq{User: "constant", Messages: []oaiMsg{
		{Role: "user", Content: "chat one"}, {Role: "assistant", Content: "answer one"},
	}}, "", tenantReq("key", "203.0.113.9", "ua"))

	res := sr.Resolve(tenantReq("key", "203.0.113.9", "ua"), &oaiReq{User: "constant", Messages: []oaiMsg{
		{Role: "user", Content: "a completely different chat"},
	}})
	if !res.IsNew {
		t.Fatalf("unrelated chat was routed into conversation %q", res.ConversationID)
	}
}

// session_key is a client-chosen string; two API keys choosing the same one
// must map to different stored conversations.
func TestSessionKeyIsScopedByAPIKey(t *testing.T) {
	a := scopedSessionKey(tenantReq("key-alice", "203.0.113.9", "ua"), "default")
	b := scopedSessionKey(tenantReq("key-bob", "203.0.113.9", "ua"), "default")
	if a == "" || b == "" || a == b {
		t.Fatalf("session_key must be namespaced per API key: %q vs %q", a, b)
	}
	if again := scopedSessionKey(tenantReq("key-alice", "198.51.100.1", "other"), "default"); again != a {
		t.Fatalf("same API key must keep the same scoped session_key: %q vs %q", again, a)
	}
	if got := scopedSessionKey(tenantReq("key-alice", "203.0.113.9", "ua"), "  "); got != "" {
		t.Fatalf("blank session_key must stay empty, got %q", got)
	}
}
