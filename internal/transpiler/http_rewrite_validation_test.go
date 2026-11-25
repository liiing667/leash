package transpiler

import (
	"strings"
	"testing"
)

func httpRewriteCedar(host, header, value string) string {
	return `
permit (
  principal,
  action == Action::"HttpRewrite",
  resource == Host::"` + host + `"
) when { context.header == "` + header + `" && context.value == "` + value + `" };`
}

func TestTranspileHTTPRewriteAcceptsOrdinaryRule(t *testing.T) {
	t.Parallel()

	tr := NewCedarToLeashTranspiler()
	_, httpRules, err := tr.TranspileFromString(httpRewriteCedar("api.example.com", "Authorization", "secrettoken"))
	if err != nil {
		t.Fatalf("ordinary rewrite policy should compile: %v", err)
	}
	if len(httpRules) != 1 {
		t.Fatalf("expected one http rewrite rule, got %d", len(httpRules))
	}
	if httpRules[0].Host != "api.example.com" || httpRules[0].Header != "Authorization" || httpRules[0].Value != "secrettoken" {
		t.Fatalf("unexpected rule: %+v", httpRules[0])
	}
}

func TestTranspileHTTPRewriteRejectsDuplicateTarget(t *testing.T) {
	t.Parallel()

	// Two policies rewriting the same host/header (different case) are
	// ambiguous: compilation must fail rather than emit both rules.
	cedar := strings.Join([]string{
		httpRewriteCedar("api.example.com", "Authorization", "Bearer one"),
		httpRewriteCedar("api.example.com", "AUTHORIZATION", "Bearer two"),
	}, "\n")

	tr := NewCedarToLeashTranspiler()
	if _, _, err := tr.TranspileFromString(cedar); err == nil {
		t.Fatal("expected duplicate host/header rewrite policies to fail compilation")
	}

	// The same header on distinct hosts remains valid.
	distinct := strings.Join([]string{
		httpRewriteCedar("a.example.com", "Authorization", "Bearer one"),
		httpRewriteCedar("b.example.com", "Authorization", "Bearer two"),
	}, "\n")
	if _, httpRules, err := tr.TranspileFromString(distinct); err != nil {
		t.Fatalf("distinct host rewrite policies should compile: %v", err)
	} else if len(httpRules) != 2 {
		t.Fatalf("expected two rewrite rules, got %d", len(httpRules))
	}
}

func TestTranspileHTTPRewriteRejectsCRLFEscapedValue(t *testing.T) {
	t.Parallel()

	// Cedar escape sequences decode into raw CR/LF at parse time; the
	// transpiler must refuse to emit such an ambiguous header value.
	cedar := httpRewriteCedar("evil.example.com", "X-Evil", "x\r\nEvil: injected")

	tr := NewCedarToLeashTranspiler()
	_, httpRules, err := tr.TranspileFromString(cedar)
	if err != nil {
		return // expected: compilation rejected the ambiguous rule
	}
	for _, rule := range httpRules {
		if strings.ContainsAny(rule.Value, "\r\n") {
			t.Fatalf("rule with CRLF value was published despite error-free compile: %+v", rule)
		}
	}
	t.Fatalf("expected CRLF rewrite policy to fail compilation, got rules: %+v", httpRules)
}
