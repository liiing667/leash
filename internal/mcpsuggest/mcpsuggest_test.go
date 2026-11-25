package mcpsuggest

import (
	"strings"
	"testing"
)

func TestNormalizeServer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"bare host", "MCP.Context7.com", "mcp.context7.com"},
		{"full url", "https://api.example.com/v1", "api.example.com"},
		{"wss with port", "wss://mcp.github.com:443/messages", "mcp.github.com"},
		{"host port", "registry.corp:8443", "registry.corp"},
		{"path only form", "api.example.com/mcp", "api.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeServer(tc.in); got != tc.want {
				t.Fatalf("NormalizeServer(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBuildStatementShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		effect      string
		server      string
		tool        string
		want        string
		wantErr     bool
		mustContain []string
	}{
		{
			name:   "server and tool scoped pair",
			effect: "forbid",
			server: "https://api.example.com/v1",
			tool:   "DB.Query",
			want:   `forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"db.query") when { resource in [ MCP::Server::"api.example.com" ] };`,
		},
		{
			name:   "host only",
			effect: "permit",
			server: "registry.corp",
			want:   `permit (principal, action == Action::"McpCall", resource) when { resource in [ MCP::Server::"registry.corp" ] };`,
		},
		{
			name:   "tool only",
			effect: "forbid",
			tool:   "danger",
			want:   `forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"danger");`,
		},
		{name: "neither identity", effect: "permit", wantErr: true},
		{name: "bad effect", effect: "maybe", server: "a.example", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildStatement(tc.effect, tc.server, tc.tool)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for _, fragment := range tc.mustContain {
				if !strings.Contains(got, fragment) {
					t.Fatalf("expected %q to contain %q", got, fragment)
				}
			}
		})
	}
}

// TestFromObservationsKeepsSameToolDifferentSourcesSeparate reproduces the
// mixed-policy bug: a tool name shared by two MCP servers must produce two
// distinct suggestions rather than one statement collapsing both sources.
func TestFromObservationsKeepsSameToolDifferentSourcesSeparate(t *testing.T) {
	t.Parallel()
	observations := []Observation{
		{Server: "https://api.example.com/v1", Tool: "search"},
		{Server: "wss://mcp.github.com:443", Tool: "search"},
		{Server: "mcp.github.com", Tool: "Search"}, // same pair, case variant -> deduped
		{Server: "registry.corp"},                  // host-only observation
		{Tool: "resolve-library-id"},               // tool-only observation
	}

	got, err := FromObservations("forbid", observations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 distinct suggestions (2 scoped pairs + host-only + tool-only), got %d: %+v", len(got), got)
	}

	pairs := make(map[string]string, len(got))
	for _, s := range got {
		pairs[s.Server+"|"+s.Tool] = s.Cedar
	}

	first, ok := pairs["api.example.com|search"]
	if !ok {
		t.Fatalf("missing api.example.com/search suggestion: %+v", got)
	}
	second, ok := pairs["mcp.github.com|search"]
	if !ok {
		t.Fatalf("missing mcp.github.com/search suggestion: %+v", got)
	}
	if first == second {
		t.Fatalf("two sources collapsed into one mixed statement: %q", first)
	}
	if !strings.Contains(first, `MCP::Server::"api.example.com"`) || !strings.Contains(first, `MCP::Tool::"search"`) {
		t.Fatalf("first suggestion lost server/tool scoping: %q", first)
	}

	hostOnly, ok := pairs["registry.corp|"]
	if !ok {
		t.Fatalf("missing host-only suggestion: %+v", got)
	}
	if strings.Contains(hostOnly, "MCP::Tool") {
		t.Fatalf("host-only suggestion should not reference a tool: %q", hostOnly)
	}

	toolOnly, ok := pairs["|resolve-library-id"]
	if !ok {
		t.Fatalf("missing tool-only suggestion: %+v", got)
	}
	if strings.Contains(toolOnly, "MCP::Server") {
		t.Fatalf("tool-only suggestion should not reference a server: %q", toolOnly)
	}
}

func TestFromObservationsDedupesRepeatedPairs(t *testing.T) {
	t.Parallel()
	observations := []Observation{
		{Server: "a.example.com", Tool: "query"},
		{Server: "a.example.com", Tool: "query"},
		{Server: "b.example.com", Tool: "query"},
	}
	got, err := FromObservations("permit", observations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 suggestions after dedupe, got %d: %+v", len(got), got)
	}
}
