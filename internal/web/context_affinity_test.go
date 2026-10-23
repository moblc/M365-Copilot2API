package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClassifyErrorRefreshRejection(t *testing.T) {
	cases := []string{
		"Refresh invalid_grant: AADSTS5000224: We are sorry, this resource is not available.",
		"token_expired: refresh token missing or expired",
	}
	for _, msg := range cases {
		if got := ClassifyError(errors.New(msg)); got != CategoryAuthExpired401 {
			t.Fatalf("ClassifyError(%q)=%v, want %v", msg, got, CategoryAuthExpired401)
		}
	}
	// A service-wide client configuration error (AADSTS7000215) is not a
	// per-account auth failure, so it must not cool accounts down.
	if got := ClassifyError(errors.New("invalid_client: AADSTS7000215: Invalid client secret provided.")); got == CategoryAuthExpired401 {
		t.Fatalf("global client error must not be classified as per-account auth: %v", got)
	}
	// A transient transport error must not be mistaken for an auth failure.
	if got := ClassifyError(errors.New("dial tcp: connection refused")); got == CategoryAuthExpired401 {
		t.Fatalf("transport error misclassified as auth failure: %v", got)
	}
}

func TestForgetAccountDropsStickyBindings(t *testing.T) {
	store := testAccountFiles(t)
	s := &Server{
		tokens:             store,
		accountPool:        newAccountHealth(),
		accountConcurrency: newAccountConcurrency(),
		contextAffinity:    newContextAffinity(),
	}
	body := &oaiReq{Messages: []oaiMsg{{Role: "user", Content: "hello world"}}}
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	first, ok := s.contextAffinity.Resolve(s, r, body)
	if !ok || first == "" {
		t.Fatalf("expected an affinity assignment, got %q ok=%v", first, ok)
	}
	hash := tenantFromRequest(r) + ":" + contextHash(body.Messages)
	s.contextAffinity.mu.Lock()
	_, bound := s.contextAffinity.byHash[hash]
	before := len(s.contextAffinity.bindings)
	s.contextAffinity.mu.Unlock()
	if !bound || before == 0 {
		t.Fatalf("expected a binding for hash %s, bound=%v n=%d", hash, bound, before)
	}

	s.contextAffinity.ForgetAccount(first)

	s.contextAffinity.mu.Lock()
	_, stillBound := s.contextAffinity.byHash[hash]
	after := len(s.contextAffinity.bindings)
	s.contextAffinity.mu.Unlock()
	if stillBound || after != 0 {
		t.Fatalf("ForgetAccount left bindings behind: byHash=%v remaining=%d", stillBound, after)
	}
}

func TestContextAffinityTenantIsolation(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "content", true: "explicit"}[explicit], func(t *testing.T) {
			s := &Server{tokens: testAccountFiles(t), accountPool: newAccountHealth(), accountConcurrency: newAccountConcurrency()}
			c := newContextAffinity()
			requests := []*http.Request{tenantReq("key-a", "203.0.113.9", "ua"), tenantReq("key-b", "203.0.113.9", "ua")}
			body := &oaiReq{Messages: []oaiMsg{{Role: "user", Content: "shared task"}}}
			for _, request := range requests {
				if explicit {
					request.Header.Set(sessionHeaderName, "shared-session")
				}
				if _, ok := c.Resolve(s, request, body); !ok {
					t.Fatal("expected account binding")
				}
			}
			if len(c.bindings) != 2 {
				t.Fatalf("tenant bindings merged: %d", len(c.bindings))
			}
			continued := &oaiReq{Messages: append(cloneMessages(body.Messages), oaiMsg{Role: "user", Content: "continue"})}
			for index, request := range requests {
				if _, ok := c.Resolve(s, request, continued); !ok {
					t.Fatal("continuation lost account binding")
				}
				c.BindConversation("bound-account", []string{"conv-a", "conv-b"}[index], "session", continued, request)
			}
			for _, binding := range c.bindings {
				want := "conv-a"
				if binding.Tenant == tenantFromRequest(requests[1]) {
					want = "conv-b"
				}
				if binding.ConversationID != want {
					t.Fatalf("tenant conversation mismatch: got %q want %q", binding.ConversationID, want)
				}
			}
			c.ForgetAccount("bound-account")
			if len(c.bindings) != 0 || len(c.byHash) != 0 || len(c.byExplicit) != 0 {
				t.Fatal("account cleanup left stale tenant indexes")
			}
		})
	}
}

func TestContextAffinityEvictionClearsTenantIndexes(t *testing.T) {
	for _, expired := range []bool{false, true} {
		c := newContextAffinity()
		c.max = 0
		lastUsed := time.Now()
		if expired {
			lastUsed = lastUsed.Add(-2 * c.ttl)
		}
		c.bindings["binding"] = contextBinding{Tenant: "tenant", Hash: "hash", ExplicitID: "session", LastUsedAt: lastUsed}
		c.byHash["tenant:hash"] = "binding"
		c.byExplicit["tenant:session"] = "binding"
		c.evictLocked(time.Now())
		if len(c.bindings) != 0 || len(c.byHash) != 0 || len(c.byExplicit) != 0 {
			t.Fatalf("eviction left stale tenant indexes (expired=%v)", expired)
		}
	}
}
