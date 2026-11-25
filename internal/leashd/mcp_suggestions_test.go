package leashd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/proxy"
)

func newSuggestionsTestAPI() *policyAPI {
	mgr := policy.NewManager(nil, func(*lsm.PolicySet, []proxy.HeaderRewriteRule) {})
	return newPolicyAPI(mgr, "", nil, nil, nil)
}

func TestHandleMCPSuggestionsPersistsPerSourceStatements(t *testing.T) {
	api := newSuggestionsTestAPI()

	body := `{
		"effect": "forbid",
		"observations": [
			{"server": "https://alpha.example.com/mcp", "tool": "search"},
			{"server": "wss://beta.example.com:443", "tool": "search"},
			{"server": "registry.corp", "tool": ""},
			{"server": "", "tool": "resolve-library-id"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/policies/mcp-suggestions", strings.NewReader(body))
	rec := httptest.NewRecorder()

	api.handleMCPSuggestions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp mcpSuggestionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if len(resp.Suggestions) != 4 {
		t.Fatalf("expected 4 per-source suggestions, got %d: %+v", len(resp.Suggestions), resp.Suggestions)
	}

	cedar := make([]string, 0, len(resp.Suggestions))
	for _, s := range resp.Suggestions {
		cedar = append(cedar, s.Cedar)
	}
	joined := strings.Join(cedar, "\n")

	mustContain := []string{
		`MCP::Server::"alpha.example.com"`,
		`MCP::Server::"beta.example.com"`,
		`MCP::Tool::"search"`,
		`MCP::Server::"registry.corp"`,
		`MCP::Tool::"resolve-library-id"`,
	}
	for _, fragment := range mustContain {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("suggestions missing %q:\n%s", fragment, joined)
		}
	}

	for _, s := range resp.Suggestions {
		if s.Server == "registry.corp" && strings.Contains(s.Cedar, "MCP::Tool") {
			t.Fatalf("host-only suggestion must not carry a tool: %q", s.Cedar)
		}
		if s.Tool == "resolve-library-id" && strings.Contains(s.Cedar, "MCP::Server") {
			t.Fatalf("tool-only suggestion must not carry a server: %q", s.Cedar)
		}
	}
}

func TestHandleMCPSuggestionsDefaultsAndValidation(t *testing.T) {
	api := newSuggestionsTestAPI()

	// GET is allowed and returns an empty (but well-formed) payload when no
	// proxy/observations are configured.
	rec := httptest.NewRecorder()
	api.handleMCPSuggestions(rec, httptest.NewRequest(http.MethodGet, "/api/policies/mcp-suggestions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d", rec.Code)
	}

	// An invalid effect falls back to the default forbid rather than erroring.
	body := `{"effect":"maybe","observations":[{"server":"a.example.com","tool":"t"}]}`
	rec = httptest.NewRecorder()
	api.handleMCPSuggestions(rec, httptest.NewRequest(http.MethodPost, "/api/policies/mcp-suggestions", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with default effect, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp mcpSuggestionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(resp.Suggestions) != 1 || resp.Suggestions[0].Effect != "forbid" {
		t.Fatalf("expected single forbid suggestion, got %+v", resp.Suggestions)
	}
}
