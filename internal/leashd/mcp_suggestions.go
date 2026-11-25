package leashd

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/strongdm/leash/internal/mcpsuggest"
)

// mcpSuggestionItem is one per-source MCP policy suggestion. Server and Tool
// carry the normalized identities; Cedar is the ready-to-persist statement.
type mcpSuggestionItem struct {
	Effect string `json:"effect"`
	Server string `json:"server,omitempty"`
	Tool   string `json:"tool,omitempty"`
	Cedar  string `json:"cedar"`
}

type mcpSuggestionsRequest struct {
	// Effect selects permit/forbid statements. Defaults to "forbid".
	Effect string `json:"effect,omitempty"`
	// Observations optionally overrides the proxy-sourced pairs. This lets
	// callers persist suggestions for identities captured out-of-band while
	// still benefiting from per-source normalization and dedupe.
	Observations []mcpsuggest.Observation `json:"observations,omitempty"`
}

type mcpSuggestionsResponse struct {
	Suggestions []mcpSuggestionItem `json:"suggestions"`
}

// handleMCPSuggestions returns one policy suggestion per observed
// (server, tool) source identity. Tool names shared across different servers
// stay separate; host-only and tool-only observations keep their shape.
func (api *policyAPI) handleMCPSuggestions(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	effect := "forbid"
	var observations []mcpsuggest.Observation
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		defer r.Body.Close()
		var req mcpSuggestionsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON payload"})
			return
		}
		if e := strings.ToLower(strings.TrimSpace(req.Effect)); e == "permit" || e == "forbid" {
			effect = e
		}
		observations = req.Observations
	}

	if len(observations) == 0 && api.mitmProxy != nil {
		for _, obs := range api.mitmProxy.SnapshotMCPToolObservations() {
			observations = append(observations, mcpsuggest.Observation{
				Server: obs.Server,
				Tool:   obs.Tool,
			})
		}
	}

	suggestions, err := mcpsuggest.FromObservations(effect, observations)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	items := make([]mcpSuggestionItem, 0, len(suggestions))
	for _, s := range suggestions {
		items = append(items, mcpSuggestionItem{
			Effect: s.Effect,
			Server: s.Server,
			Tool:   s.Tool,
			Cedar:  s.Cedar,
		})
	}
	writeJSON(w, http.StatusOK, mcpSuggestionsResponse{Suggestions: items})
}
