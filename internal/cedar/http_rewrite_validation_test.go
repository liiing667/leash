package cedar

import (
	"strings"
	"testing"
)

func rewritePolicy(host, header, value string) string {
	return `permit (
  principal,
  action == Action::"HttpRewrite",
  resource == Host::"` + host + `"
) when { context.header == "` + header + `" && context.value == "` + value + `" };`
}

func TestCompileStringAcceptsOrdinaryHTTPRewrite(t *testing.T) {
	t.Parallel()

	comp, err := CompileString("policies", rewritePolicy("api.example.com", "Authorization", "secrettoken"))
	if err != nil {
		t.Fatalf("ordinary rewrite policy should compile: %v", err)
	}
	if len(comp.HTTPRules) != 1 {
		t.Fatalf("expected one rewrite rule, got %d", len(comp.HTTPRules))
	}
}

func TestCompileStringRejectsAmbiguousHTTPRewrite(t *testing.T) {
	t.Parallel()

	// Duplicate host/header target across two policies.
	duplicate := strings.Join([]string{
		rewritePolicy("api.example.com", "Authorization", "one"),
		rewritePolicy("api.example.com", "authorization", "two"),
	}, "\n")
	if comp, err := CompileString("policies", duplicate); err == nil {
		t.Fatalf("expected duplicate rewrite targets to fail compilation, got %+v", comp.HTTPRules)
	}

	// Raw CR/LF delivered through Cedar escape sequences.
	crlf := rewritePolicy("evil.example.com", "X-Evil", "x\r\nEvil: injected")
	comp, err := CompileString("policies", crlf)
	if err != nil {
		return
	}
	for _, rule := range comp.HTTPRules {
		if strings.ContainsAny(rule.Value, "\r\n") {
			t.Fatalf("CRLF rewrite rule was published: %+v", rule)
		}
	}
	t.Fatalf("expected CRLF rewrite policy to fail compilation, got %+v", comp.HTTPRules)
}
