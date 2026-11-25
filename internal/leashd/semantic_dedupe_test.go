package leashd

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/transpiler"
)

func TestSemanticPolicyEqualityIgnoresSetOrder(t *testing.T) {
	parser := transpiler.NewCedarParser()
	first := mustParseFirstPolicy(t, parser, `permit (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"a.example", Host::"b.example"] };`)
	second := mustParseFirstPolicy(t, parser, `permit (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"b.example", Host::"a.example"] };`)

	if !policiesAreEquivalent(first, second) {
		t.Fatal("policies with reordered set objects must have the same semantic identity")
	}
}

func TestSemanticConflictStillDetectedAcrossSetOrder(t *testing.T) {
	parser := transpiler.NewCedarParser()
	permit := mustParseFirstPolicy(t, parser, `permit (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"a.example", Host::"b.example"] };`)
	forbid := mustParseFirstPolicy(t, parser, `forbid (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"b.example", Host::"a.example"] };`)

	if !policiesConflict(permit, forbid) {
		t.Fatal("reordered semantic sets must still identify an allow/deny conflict")
	}
}

func TestDedupeCedarStatementsUsesSemanticIdentity(t *testing.T) {
	first := `permit (principal, action == Action::"NetworkConnect", resource) when { resource in [Host::"a.example", Host::"b.example"] };`
	second := `permit(principal,action==Action::"NetworkConnect",resource) when { resource in [Host::"b.example",Host::"a.example"] };`

	got := dedupeCedarStatements([]string{first, second})
	if len(got) != 1 {
		t.Fatalf("expected one semantic statement, got %d: %#v", len(got), got)
	}
	if !strings.Contains(got[0], `Host::"a.example"`) {
		t.Fatalf("expected first operator-authored representation to be retained, got %q", got[0])
	}
}

func mustParseFirstPolicy(t *testing.T, parser *transpiler.CedarParser, src string) transpiler.CedarPolicy {
	t.Helper()
	set, err := parser.ParseFromString(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Policies) == 0 {
		t.Fatal("no policy parsed")
	}
	return set.Policies[0]
}
