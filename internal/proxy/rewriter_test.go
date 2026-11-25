package proxy

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validRule() HeaderRewriteRule {
	return HeaderRewriteRule{Host: "example.com", Header: "Authorization", Value: "Bearer token"}
}

func TestValidateHeaderRewriteRuleAcceptsOrdinaryRules(t *testing.T) {
	t.Parallel()

	cases := []HeaderRewriteRule{
		{Host: "example.com", Header: "Authorization", Value: "Bearer demo-secret123"},
		{Host: "example.com", Header: "X-Custom-Header", Value: "value with spaces"},
		{Host: "example.com", Header: "X-Tab", Value: "value\twith\ttabs"},
		{Host: "example.com", Header: "Empty-Value", Value: ""},
	}
	for _, rule := range cases {
		if err := ValidateHeaderRewriteRule(rule); err != nil {
			t.Errorf("expected rule %+v to be accepted, got %v", rule, err)
		}
	}
}

func TestValidateHeaderRewriteRuleRejectsCRLF(t *testing.T) {
	t.Parallel()

	cases := []HeaderRewriteRule{
		{Host: "example.com", Header: "X-Inject\r\nEvil: 1", Value: "v"},
		{Host: "example.com", Header: "X-Inject\nEvil: 1", Value: "v"},
		{Host: "example.com", Header: "X-Inject\rEvil: 1", Value: "v"},
		{Host: "example.com", Header: "Authorization", Value: "Bearer x\r\nEvil: injected"},
		{Host: "example.com", Header: "Authorization", Value: "Bearer x\nEvil: injected"},
		{Host: "example.com", Header: "Authorization", Value: "line1\r\nline2"},
		{Host: "example.com", Header: "Bad\x00Name", Value: "v"},
		{Host: "example.com", Header: "Authorization", Value: "nul\x00value"},
	}
	for _, rule := range cases {
		if err := ValidateHeaderRewriteRule(rule); err == nil {
			t.Errorf("expected ambiguous rule to be rejected: %+v", rule)
		}
	}
}

func TestValidateHeaderRewriteRuleRejectsEmptyFields(t *testing.T) {
	t.Parallel()

	cases := []HeaderRewriteRule{
		{Host: "", Header: "Authorization", Value: "v"},
		{Host: "   ", Header: "Authorization", Value: "v"},
		{Host: "example.com", Header: "", Value: "v"},
		{Host: "example.com", Header: "   ", Value: "v"},
	}
	for _, rule := range cases {
		if err := ValidateHeaderRewriteRule(rule); err == nil {
			t.Errorf("expected rule with empty fields to be rejected: %+v", rule)
		}
	}
}

func TestValidateHeaderRewriteRulesRejectsDuplicateTarget(t *testing.T) {
	t.Parallel()

	// Same host + same header (case-insensitive) is ambiguous even when the
	// values differ, because the last writer would silently win.
	rules := []HeaderRewriteRule{
		{Host: "example.com", Header: "Authorization", Value: "Bearer one"},
		{Host: "example.com", Header: "authorization", Value: "Bearer two"},
	}
	if err := ValidateHeaderRewriteRules(rules); err == nil {
		t.Fatal("expected duplicate host/header target to be rejected")
	}

	// The same header on different hosts is fine.
	ok := []HeaderRewriteRule{
		{Host: "a.example.com", Header: "Authorization", Value: "Bearer one"},
		{Host: "b.example.com", Header: "Authorization", Value: "Bearer two"},
	}
	if err := ValidateHeaderRewriteRules(ok); err != nil {
		t.Fatalf("expected distinct host targets to be accepted, got %v", err)
	}

	// Different headers on the same host are fine.
	ok = []HeaderRewriteRule{
		{Host: "example.com", Header: "Authorization", Value: "Bearer one"},
		{Host: "example.com", Header: "X-Trace", Value: "trace"},
	}
	if err := ValidateHeaderRewriteRules(ok); err != nil {
		t.Fatalf("expected distinct header targets to be accepted, got %v", err)
	}
}

func TestSetRulesRejectsAmbiguousBatchAndKeepsPreviousRules(t *testing.T) {
	t.Parallel()

	rewriter := NewHeaderRewriter()
	good := []HeaderRewriteRule{validRule()}
	if err := rewriter.SetRules(good); err != nil {
		t.Fatalf("initial SetRules failed: %v", err)
	}

	bad := []HeaderRewriteRule{
		validRule(),
		{Host: "example.com", Header: "Authorization", Value: "Bearer x\r\nEvil: injected"},
	}
	if err := rewriter.SetRules(bad); err == nil {
		t.Fatal("expected SetRules to reject a batch containing CRLF")
	}

	rewriter.mutex.RLock()
	got := append([]HeaderRewriteRule(nil), rewriter.rules...)
	rewriter.mutex.RUnlock()
	if len(got) != 1 || got[0].Value != "Bearer token" {
		t.Fatalf("previous rules must remain active after a rejected batch, got %+v", got)
	}

	duplicate := []HeaderRewriteRule{
		{Host: "example.com", Header: "Authorization", Value: "Bearer one"},
		{Host: "example.com", Header: "authorization", Value: "Bearer two"},
	}
	if err := rewriter.SetRules(duplicate); err == nil {
		t.Fatal("expected SetRules to reject a batch with duplicate targets")
	}
	rewriter.mutex.RLock()
	got = append([]HeaderRewriteRule(nil), rewriter.rules...)
	rewriter.mutex.RUnlock()
	if len(got) != 1 || got[0].Value != "Bearer token" {
		t.Fatalf("previous rules must remain active after a rejected duplicate batch, got %+v", got)
	}
}

func TestSetRulesAcceptsEmptyAndValidBatches(t *testing.T) {
	t.Parallel()

	rewriter := NewHeaderRewriter()
	if err := rewriter.SetRules(nil); err != nil {
		t.Fatalf("empty rule set should be accepted: %v", err)
	}
	if err := rewriter.SetRules([]HeaderRewriteRule{validRule()}); err != nil {
		t.Fatalf("valid rule set should be accepted: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "example.com"
	rewriter.ApplyRules(req)
	if got := req.Header.Get("Authorization"); got != "Bearer token" {
		t.Fatalf("expected rule to be applied, got %q", got)
	}
}

func TestApplyRulesSkipsAmbiguousRuleAtDataPlane(t *testing.T) {
	t.Parallel()

	rewriter := NewHeaderRewriter()
	// Bypass ingestion validation to simulate an ambiguous rule that reached
	// the data plane through an older/alternate path.
	rewriter.mutex.Lock()
	rewriter.rules = []HeaderRewriteRule{
		{Host: "example.com", Header: "X-Evil", Value: "x\r\nEvil: injected"},
		{Host: "example.com", Header: "X-Good", Value: "safe"},
	}
	rewriter.mutex.Unlock()

	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "example.com"
	rewriter.ApplyRules(req)

	if got := req.Header.Get("X-Evil"); got != "" {
		t.Fatalf("ambiguous rule must never be applied, got %q", got)
	}
	if got := req.Header.Get("X-Good"); got != "safe" {
		t.Fatalf("ordinary rule should still apply, got %q", got)
	}
}

func TestLoadRulesFromFileRejectsAmbiguousFileWithoutPartialPublish(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	goodPath := filepath.Join(dir, "good.txt")
	goodContent := strings.Join([]string{
		"# comment",
		"example.com:Authorization:Bearer token",
		"other.example.com:X-Trace:trace value",
		"",
	}, "\n")
	if err := os.WriteFile(goodPath, []byte(goodContent), 0o644); err != nil {
		t.Fatalf("write good config: %v", err)
	}

	rewriter := NewHeaderRewriter()
	if err := rewriter.LoadRulesFromFile(goodPath); err != nil {
		t.Fatalf("LoadRulesFromFile with valid content failed: %v", err)
	}

	badPath := filepath.Join(dir, "bad.txt")
	badContent := strings.Join([]string{
		"example.com:Authorization:Bearer token",
		"example.com:authorization:Bearer duplicate",
		"evil.example.com:X-Inject:Bearer x\r\nEvil: injected",
	}, "\n")
	if err := os.WriteFile(badPath, []byte(badContent), 0o644); err != nil {
		t.Fatalf("write bad config: %v", err)
	}

	if err := rewriter.LoadRulesFromFile(badPath); err == nil {
		t.Fatal("expected LoadRulesFromFile to reject ambiguous rules")
	}

	rewriter.mutex.RLock()
	got := append([]HeaderRewriteRule(nil), rewriter.rules...)
	rewriter.mutex.RUnlock()
	if len(got) != 2 {
		t.Fatalf("previous valid rules must remain after failed load, got %d rules: %+v", len(got), got)
	}
	for _, rule := range got {
		if rule.Host == "evil.example.com" || strings.Contains(rule.Value, "\r") || strings.Contains(rule.Value, "\n") {
			t.Fatalf("ambiguous rule was published after failed load: %+v", got)
		}
	}
}
