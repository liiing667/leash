// Package mcpsuggest turns observed MCP traffic into Cedar policy suggestions.
//
// Observed tool calls are persisted as (server, tool) pairs keyed by source
// identity so that a tool name served by two different MCP servers yields two
// distinct suggestions instead of one cross-paired, "mixed" statement. The
// three non-paired shapes remain supported:
//
//   - full URL servers (normalized to host-only Cedar entities)
//   - host-only (server-only) policies
//   - tool-only policies (no server identity observed)
package mcpsuggest

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// Observation is a single observed MCP tool call tied to its source server.
// Server may be empty when the source identity is unknown (tool-only case).
type Observation struct {
	Server string
	Tool   string
}

// Suggestion is a ready-to-persist Cedar statement for one MCP observation.
type Suggestion struct {
	Effect string
	Server string // normalized host identity; empty for tool-only suggestions
	Tool   string // empty for host-only suggestions
	Cedar  string
}

// NormalizeServer reduces a free-form MCP server reference (full URL,
// host:port, or bare host) to the stable host identity used in Cedar
// MCP::Server entities. An empty input returns an empty string.
func NormalizeServer(server string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u != nil {
			if host := u.Hostname(); host != "" {
				s = host
			}
		}
	}
	if strings.Contains(s, "/") {
		s = strings.SplitN(s, "/", 2)[0]
	}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		s = host
	}
	return strings.TrimSpace(s)
}

// NormalizeTool lowercases and trims an MCP tool name.
func NormalizeTool(tool string) string {
	return strings.ToLower(strings.TrimSpace(tool))
}

func escapeCedarString(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return escaped
}

// BuildStatement renders a single Cedar McpCall statement.
//
//   - server + tool: scoped tool policy (resource == Tool, when in Server)
//   - server only:   host-only policy (resource in [ Server ])
//   - tool only:     tool-only policy (resource == Tool)
//
// effect must be "permit" or "forbid".
func BuildStatement(effect, server, tool string) (string, error) {
	effect = strings.ToLower(strings.TrimSpace(effect))
	if effect != "permit" && effect != "forbid" {
		return "", errors.New("effect must be permit or forbid")
	}
	server = NormalizeServer(server)
	tool = NormalizeTool(tool)
	switch {
	case server != "" && tool != "":
		return effect + ` (principal, action == Action::"McpCall", resource == MCP::Tool::"` +
			escapeCedarString(tool) + `") when { resource in [ MCP::Server::"` +
			escapeCedarString(server) + `" ] };`, nil
	case server != "":
		return effect + ` (principal, action == Action::"McpCall", resource) when { resource in [ MCP::Server::"` +
			escapeCedarString(server) + `" ] };`, nil
	case tool != "":
		return effect + ` (principal, action == Action::"McpCall", resource == MCP::Tool::"` +
			escapeCedarString(tool) + `");`, nil
	default:
		return "", errors.New("mcp suggestion requires a server or tool identity")
	}
}

// FromObservations builds one deduplicated suggestion per distinct
// (server, tool) source identity. Observations sharing a tool name but
// differing by server produce separate suggestions; the same pair observed
// repeatedly collapses to a single most-recent-first suggestion.
func FromObservations(effect string, observations []Observation) ([]Suggestion, error) {
	seen := make(map[string]struct{}, len(observations))
	out := make([]Suggestion, 0, len(observations))
	for _, obs := range observations {
		server := NormalizeServer(obs.Server)
		tool := NormalizeTool(obs.Tool)
		if server == "" && tool == "" {
			continue
		}
		key := effect + "|" + server + "|" + tool
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		cedar, err := BuildStatement(effect, server, tool)
		if err != nil {
			return nil, err
		}
		out = append(out, Suggestion{
			Effect: strings.ToLower(strings.TrimSpace(effect)),
			Server: server,
			Tool:   tool,
			Cedar:  cedar,
		})
	}
	return out, nil
}
