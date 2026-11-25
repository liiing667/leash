package suggest

import (
	"reflect"
	"strings"
	"testing"
)

func TestCanonicalCedarIdentityIgnoresObjectAndStatementOrder(t *testing.T) {
	first := `
// operator authored
permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"b.example", Host::"a.example" ] };

forbid (principal, action == Action::"FileOpen", resource == File::"/etc/shadow");
`
	second := `forbid(principal,action==Action::"FileOpen",resource==File::"/etc/shadow");
permit(principal,action==Action::"NetworkConnect",resource) when { resource in [Host::"a.example",Host::"b.example",Host::"a.example"] };`

	if got, want := CanonicalCedarIdentity(second), CanonicalCedarIdentity(first); got != want {
		t.Fatalf("semantic identities differ\nwant: %q\ngot:  %q", want, got)
	}

	duplicated := first + "\n" + strings.ReplaceAll(first, `Host::"b.example", Host::"a.example"`, `Host::"a.example", Host::"b.example"`)
	if got, want := CanonicalCedarIdentity(duplicated), CanonicalCedarIdentity(first); got != want {
		t.Fatalf("duplicate policy statements must not change identity\nwant: %q\ngot:  %q", want, got)
	}
}

func TestDeduplicateMergesEvidenceButKeepsDistinctPolicies(t *testing.T) {
	cedar := `permit (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"a.example", Host::"b.example"] };`
	reordered := `permit (principal,
		action == Action::"NetworkConnect",
		resource) when { resource in [Host::"b.example",Host::"a.example"] };`

	items := []Suggestion{
		{
			Kind:          SuggestDomain,
			ProposedCedar: cedar,
			PolicyCount:   2,
			PolicyRefs: []PolicyReference{{
				Effect: "permit", Operation: "connect", Target: "a.example", Source: "runtime",
				Metadata: map[string]string{"port": "443"},
			}},
		},
		{
			Kind:          SuggestDomain,
			ProposedCedar: reordered,
			PolicyCount:   1,
			PolicyRefs: []PolicyReference{{
				Effect: "permit", Operation: "connect", Target: "b.example", Source: "file",
				Metadata: map[string]string{"port": "443"},
			}},
		},
		{
			Kind:          SuggestDomain,
			ProposedCedar: `permit (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"c.example"] };`,
			PolicyCount:   1,
			PolicyRefs:    []PolicyReference{{Effect: "permit", Operation: "connect", Target: "c.example", Source: "file"}},
		},
	}

	got := Deduplicate(items)
	if len(got) != 2 {
		t.Fatalf("expected one merged suggestion and one distinct suggestion, got %d: %#v", len(got), got)
	}
	if got[0].PolicyCount != 2 {
		t.Fatalf("expected policy count not to be inflated by duplicate evidence, got %d", got[0].PolicyCount)
	}
	sources := make(map[string]bool)
	for _, ref := range got[0].PolicyRefs {
		sources[ref.Source] = true
	}
	if !reflect.DeepEqual(sources, map[string]bool{"runtime": true, "file": true}) {
		t.Fatalf("expected both source evidence entries, got %#v", got[0].PolicyRefs)
	}
}

func TestDeduplicateWorkflowSuggestionsUsesMinedPatternNotClusterNumber(t *testing.T) {
	items := []Suggestion{
		{
			Kind:        SuggestWorkflow,
			Summary:     "Workflow cluster-1 (2 sessions)",
			PolicyCount: 2,
			Metadata: map[string]string{
				"cluster_id":  "cluster-1",
				"top_pattern": "file:open:unix.file:/etc/ssh -> network:connect:http.host:api.example",
				"psi":         "0.010",
				"drift_flag":  "false",
			},
			PolicyRefs: []PolicyReference{{Source: "runtime", Operation: "connect", Target: "api.example"}},
		},
		{
			Kind:        SuggestWorkflow,
			Summary:     "Workflow cluster-2 (3 sessions)",
			PolicyCount: 3,
			Metadata: map[string]string{
				"cluster_id":  "cluster-2",
				"top_pattern": "file:open:unix.file:/etc/ssh -> network:connect:http.host:api.example",
				"psi":         "0.020",
				"drift_flag":  "true",
			},
			PolicyRefs: []PolicyReference{{Source: "file", Operation: "connect", Target: "api.example"}},
		},
	}

	got := Deduplicate(items)
	if len(got) != 1 {
		t.Fatalf("expected one semantic workflow suggestion, got %d", len(got))
	}
	if len(got[0].PolicyRefs) != 2 {
		t.Fatalf("expected both workflow evidence entries, got %#v", got[0].PolicyRefs)
	}
}

func TestSemanticIdentityKeepsDifferentPortsDistinct(t *testing.T) {
	cedar := `permit (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"*.example"] };`
	http := Suggestion{Kind: SuggestDomain, ProposedCedar: cedar, Metadata: map[string]string{"port": "443"}}
	tlsAlt := Suggestion{Kind: SuggestDomain, ProposedCedar: cedar, Metadata: map[string]string{"port": "8443"}}

	if SemanticIdentity(http) == SemanticIdentity(tlsAlt) {
		t.Fatal("suggestions for different destination ports must remain semantically distinct")
	}
	if got := Deduplicate([]Suggestion{http, tlsAlt}); len(got) != 2 {
		t.Fatalf("expected both port-scoped suggestions, got %d", len(got))
	}
}
