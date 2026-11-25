package proxy

import (
	"strconv"
	"strings"
	"testing"
)

func TestNormalizeMCPServerIdentity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"https://api.example.com/v1", "api.example.com"},
		{"wss://mcp.github.com:443/messages", "mcp.github.com"},
		{"registry.corp:8443", "registry.corp"},
		{"MCP.Context7.com", "mcp.context7.com"},
	}
	for _, tc := range cases {
		if got := normalizeMCPServerIdentity(tc.in); got != tc.want {
			t.Errorf("normalizeMCPServerIdentity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRememberPairKeepsToolSourcesDistinct(t *testing.T) {
	t.Parallel()
	var pairs []MCPToolObservation
	pairs = rememberPair(pairs, MCPToolObservation{Server: "api.example.com", Tool: "search"}, maxObservedPairs)
	pairs = rememberPair(pairs, MCPToolObservation{Server: "mcp.github.com", Tool: "search"}, maxObservedPairs)

	if len(pairs) != 2 {
		t.Fatalf("expected two distinct (server, tool) pairs, got %d: %+v", len(pairs), pairs)
	}

	// Re-observing the same pair moves it to the front rather than duplicating.
	pairs = rememberPair(pairs, MCPToolObservation{Server: "mcp.github.com", Tool: "SEARCH"}, maxObservedPairs)
	if len(pairs) != 2 {
		t.Fatalf("case-insensitive re-observation must dedupe, got %d: %+v", len(pairs), pairs)
	}
	// Most-recent-first ordering; the newest observation's casing is retained,
	// matching the flat rememberValue hint convention.
	if got := pairs[0]; got.Server != "mcp.github.com" || !strings.EqualFold(got.Tool, "search") {
		t.Fatalf("expected re-observed pair first, got %+v", pairs)
	}

	// Tool-only observations remain a distinct identity.
	pairs = rememberPair(pairs, MCPToolObservation{Server: "", Tool: "search"}, maxObservedPairs)
	if len(pairs) != 3 {
		t.Fatalf("expected tool-only pair to be retained separately, got %d: %+v", len(pairs), pairs)
	}
}

func TestObserverSnapshotsPerSourceToolObservations(t *testing.T) {
	t.Parallel()
	observer := newMCPObserver(MCPConfig{Mode: MCPModeBasic}, nil)

	observer.rememberToolOnServer("search", "https://api.example.com/v1")
	observer.rememberToolOnServer("search", "wss://mcp.github.com:443")
	observer.rememberToolOnServer("Search", "mcp.github.com") // same pair, different case
	observer.rememberToolOnServer("resolve-library-id", "")   // tool-only

	flat := observer.SnapshotTools()
	if len(flat) != 2 {
		t.Fatalf("flat tool list should keep unique tool names, got %+v", flat)
	}

	pairs := observer.SnapshotToolObservations()
	if len(pairs) != 3 {
		t.Fatalf("expected 3 per-source pairs (two hosts + tool-only), got %d: %+v", len(pairs), pairs)
	}

	seen := map[string]bool{}
	for _, p := range pairs {
		seen[strings.ToLower(p.Server)+"|"+strings.ToLower(p.Tool)] = true
	}
	for _, key := range []string{
		"api.example.com|search",
		"mcp.github.com|search",
		"|resolve-library-id",
	} {
		if !seen[key] {
			t.Fatalf("missing expected pair %q in %+v", key, pairs)
		}
	}
}

func TestRememberPairRespectsLimit(t *testing.T) {
	t.Parallel()
	var pairs []MCPToolObservation
	for i := 0; i < maxObservedPairs+5; i++ {
		pairs = rememberPair(pairs, MCPToolObservation{
			Server: "host.example.com",
			Tool:   "tool-" + strconv.Itoa(i),
		}, maxObservedPairs)
	}
	if len(pairs) != maxObservedPairs {
		t.Fatalf("pair list should be bounded at %d, got %d", maxObservedPairs, len(pairs))
	}
}
