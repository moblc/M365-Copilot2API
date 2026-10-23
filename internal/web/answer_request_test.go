package web

import (
	"encoding/json"
	"strings"
	"testing"

	"m365-copilot2api/internal/chathub"
)

func TestReplayAnswerRequestClearsUpstreamState(t *testing.T) {
	original := chathub.Request{
		Text: "incremental message",
		ConversationID: "account-a-conversation",
		SessionID: "account-a-session",
		ConversationSignature: "account-a-signature",
		PreviousMessages: []chathub.ContextMessage{{Author: "user", Description: "old context"}},
		Started: true,
		Tone: "magic",
		Tools: []chathub.Tool{{Type: "function", Function: json.RawMessage(`{"name":"read_file"}`)}},
	}
	fullPrompt := "[user]\noriginal task\n[assistant]\nprevious answer\n[user]\ncontinue"
	replayed := replayAnswerRequest(original, fullPrompt, nil)
	if replayed.Text != fullPrompt {
		t.Fatal("failover lost full conversation history")
	}
	if replayed.ConversationID != "" || replayed.SessionID != "" || replayed.ConversationSignature != "" || len(replayed.PreviousMessages) != 0 || replayed.Started {
		t.Fatalf("failover retained previous account state: %#v", replayed)
	}
	if replayed.Tone != original.Tone || len(replayed.Tools) != len(original.Tools) {
		t.Fatal("failover lost request configuration")
	}
	if original.ConversationID != "account-a-conversation" || original.Text != "incremental message" {
		t.Fatal("replay mutated the original request")
	}
}

func answerRequestTestBody() oaiReq {
	return oaiReq{
		ConversationID: "conversation-1",
		SessionID:      "session-1",
		Tools: []chathub.Tool{{
			Type:     "function",
			Function: json.RawMessage(`{"name":"read_file","parameters":{"type":"object"}}`),
		}},
		ToolChoice: "auto",
	}
}

func TestBuildAnswerRequestRouterOmitsNativePlugins(t *testing.T) {
	req := buildAnswerRequest("[user]\nhello", "magic", answerRequestTestBody(), agentLedger{}, "router", "", runtimeSettings{}, chathub.FeatureFlags{}, chathubLocale{}, false)
	if len(req.Tools) != 0 || req.ToolChoice != nil {
		t.Fatalf("router answer leaked native tools: tools=%d choice=%#v", len(req.Tools), req.ToolChoice)
	}
	if req.Text != "[user]\nhello" {
		t.Fatalf("empty ledger changed answer prompt: %q", req.Text)
	}
}

func TestBuildAnswerRequestNativeForwardsTools(t *testing.T) {
	req := buildAnswerRequest("[user]\nhello", "magic", answerRequestTestBody(), agentLedger{}, "native", "", runtimeSettings{}, chathub.FeatureFlags{}, chathubLocale{}, false)
	if len(req.Tools) != 1 || req.ToolChoice != "auto" {
		t.Fatalf("native answer lost tools: tools=%d choice=%#v", len(req.Tools), req.ToolChoice)
	}
}

func TestBuildAnswerRequestAddsCompletedEvidence(t *testing.T) {
	ledger := agentLedger{Completed: []toolEvidence{{ID: "call_1", Name: "read_file", Arguments: `{}`, Result: "ok"}}}
	req := buildAnswerRequest("[user]\nsummarize", "magic", answerRequestTestBody(), ledger, "router", "", runtimeSettings{}, chathub.FeatureFlags{}, chathubLocale{}, false)
	for _, want := range []string{"EVIDENCE_LEDGER:", "Report only actions supported by completed tool results"} {
		if !strings.Contains(req.Text, want) {
			t.Fatalf("answer prompt missing %q: %s", want, req.Text)
		}
	}
}

func TestBuildAnswerRequestMCPForwardsTools(t *testing.T) {
	req := buildAnswerRequest("[user]\nhello", "magic", answerRequestTestBody(), agentLedger{}, "router", "http://127.0.0.1:4142/v1/mcp/sse", runtimeSettings{}, chathub.FeatureFlags{}, chathubLocale{}, false)
	if !req.DisableCodeInterpreter {
		t.Fatal("MCP answer re-enabled the built-in code interpreter")
	}
	if len(req.Tools) != 1 || req.ToolChoice != "auto" {
		t.Fatalf("MCP answer lost tools: tools=%d choice=%#v", len(req.Tools), req.ToolChoice)
	}
	if req.MCPServerURL != "http://127.0.0.1:4142/v1/mcp/sse" {
		t.Fatalf("MCP URL not set: %q", req.MCPServerURL)
	}
}

func TestBuildAnswerRequestDisablesCodeInterpreterForTools(t *testing.T) {
	for _, mode := range []string{"router", "native"} {
		for _, choice := range []string{"auto", "required", "none"} {
			t.Run(mode+"/"+choice, func(t *testing.T) {
				body := answerRequestTestBody()
				body.ToolChoice = choice
				ledger := agentLedger{Completed: []toolEvidence{{ID: "call_1", Name: "read_file", Arguments: `{}`, Result: "ok"}}}
				req := buildAnswerRequest("[user]\nsummarize", "magic", body, ledger, mode, "", runtimeSettings{}, chathub.FeatureFlags{}, chathubLocale{}, false)
				if !req.DisableCodeInterpreter {
					t.Fatal("tool answer re-enabled the built-in code interpreter")
				}
			})
		}
	}
	req := buildAnswerRequest("hello", "magic", oaiReq{}, agentLedger{}, "router", "", runtimeSettings{}, chathub.FeatureFlags{}, chathubLocale{}, false)
	if req.DisableCodeInterpreter {
		t.Fatal("ordinary chat unexpectedly disabled the code interpreter")
	}
}
