package policy

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
)

func TestParseHTTPRuleStringAcceptsOrdinaryRules(t *testing.T) {
	t.Parallel()

	cases := []string{
		"allow http.rewrite example.com header:Authorization:Bearer demo-secret123",
		"allow http.rewrite example.com header:X-Trace:trace value with spaces",
		"allow http.rewrite example.com header:Empty:",
	}
	for _, input := range cases {
		rule, err := ParseHTTPRuleString(input)
		if err != nil {
			t.Errorf("expected %q to parse, got %v", input, err)
			continue
		}
		if rule.Host != "example.com" {
			t.Errorf("expected host example.com, got %q", rule.Host)
		}
	}
}

func TestParseHTTPRuleStringRejectsAmbiguousHeaders(t *testing.T) {
	t.Parallel()

	cases := []string{
		"allow http.rewrite example.com header:X-Inject\r\nEvil: 1:v",
		"allow http.rewrite example.com header:X-Inject\nEvil: 1:v",
		"allow http.rewrite example.com header:Authorization:Bearer x\r\nEvil: injected",
		"allow http.rewrite example.com header:Authorization:line1\nline2",
		"allow http.rewrite example.com header:Bad\x00Name:v",
		"allow http.rewrite example.com header::v",
	}
	for _, input := range cases {
		if _, err := ParseHTTPRuleString(input); err == nil {
			t.Errorf("expected ambiguous rule to be rejected: %q", input)
		}
	}
}

func TestManagerAddRuleRejectsDuplicateTargetWithoutPartialPublish(t *testing.T) {
	t.Parallel()

	var published []proxy.HeaderRewriteRule
	mgr := NewManager(nil, func(_ *lsm.PolicySet, httpRules []proxy.HeaderRewriteRule) {
		published = append([]proxy.HeaderRewriteRule(nil), httpRules...)
	})

	first := "allow http.rewrite example.com header:Authorization:Bearer one"
	if err := mgr.AddRule(first); err != nil {
		t.Fatalf("first AddRule failed: %v", err)
	}

	// Same host/header in different case is ambiguous.
	duplicate := "allow http.rewrite example.com header:AUTHORIZATION:Bearer two"
	if err := mgr.AddRule(duplicate); err == nil {
		t.Fatal("expected duplicate host/header AddRule to fail")
	}

	// A CRLF rule must also be rejected.
	injected := "allow http.rewrite example.com header:X-Evil:Bearer x\r\nEvil: injected"
	if err := mgr.AddRule(injected); err == nil {
		t.Fatal("expected CRLF AddRule to fail")
	}

	_, active := mgr.GetActiveRules()
	if len(active) != 1 {
		t.Fatalf("expected only the original rule to remain active, got %d: %+v", len(active), active)
	}
	if active[0].Value != "Bearer one" {
		t.Fatalf("original rule mutated after failed adds: %+v", active[0])
	}

	// The proxy callback must never have observed a partial set.
	if len(published) != 1 || !strings.Contains(published[0].Value, "Bearer one") {
		t.Fatalf("proxy callback observed partial publication: %+v", published)
	}

	// Ordinary add for a distinct target still works.
	other := "allow http.rewrite example.com header:X-Trace:trace"
	if err := mgr.AddRule(other); err != nil {
		t.Fatalf("ordinary AddRule should keep working: %v", err)
	}
	_, active = mgr.GetActiveRules()
	if len(active) != 2 {
		t.Fatalf("expected two active rules after ordinary add, got %d", len(active))
	}
}

func TestManagerSetRuntimeRulesRejectsAmbiguousBatchAtomically(t *testing.T) {
	t.Parallel()

	mgr := NewManager(nil, func(_ *lsm.PolicySet, _ []proxy.HeaderRewriteRule) {})

	good := []proxy.HeaderRewriteRule{
		{Host: "example.com", Header: "Authorization", Value: "Bearer one"},
	}
	if err := mgr.SetRuntimeRules(&lsm.PolicySet{}, good); err != nil {
		t.Fatalf("initial SetRuntimeRules failed: %v", err)
	}

	bad := []proxy.HeaderRewriteRule{
		{Host: "example.com", Header: "Authorization", Value: "Bearer one"},
		{Host: "example.com", Header: "authorization", Value: "Bearer two"},
	}
	if err := mgr.SetRuntimeRules(&lsm.PolicySet{}, bad); err == nil {
		t.Fatal("expected SetRuntimeRules to reject duplicate targets")
	}

	crlf := []proxy.HeaderRewriteRule{
		{Host: "evil.example.com", Header: "X-Evil", Value: "x\r\nEvil: injected"},
	}
	if err := mgr.SetRuntimeRules(&lsm.PolicySet{}, crlf); err == nil {
		t.Fatal("expected SetRuntimeRules to reject CRLF rules")
	}

	_, active := mgr.GetActiveRules()
	if len(active) != 1 || active[0].Value != "Bearer one" {
		t.Fatalf("previous runtime rules must remain after failed updates, got %+v", active)
	}
}

func TestManagerUpdateFileRulesRejectsAmbiguousBatch(t *testing.T) {
	t.Parallel()

	mgr := NewManager(nil, func(_ *lsm.PolicySet, _ []proxy.HeaderRewriteRule) {})

	good := []proxy.HeaderRewriteRule{
		{Host: "example.com", Header: "Authorization", Value: "Bearer one"},
	}
	if err := mgr.UpdateFileRules(&lsm.PolicySet{}, good); err != nil {
		t.Fatalf("initial UpdateFileRules failed: %v", err)
	}

	bad := []proxy.HeaderRewriteRule{
		{Host: "example.com", Header: "X-Evil", Value: "x\r\nEvil: injected"},
	}
	if err := mgr.UpdateFileRules(&lsm.PolicySet{}, bad); err == nil {
		t.Fatal("expected UpdateFileRules to reject a CRLF rule")
	}

	_, fileHTTP, _, _ := mgr.Snapshot()
	if len(fileHTTP) != 1 || fileHTTP[0].Value != "Bearer one" {
		t.Fatalf("file layer must remain unchanged after failed update, got %+v", fileHTTP)
	}
}
