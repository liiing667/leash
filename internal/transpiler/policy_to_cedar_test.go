package transpiler

import (
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
)

func TestPolicySetToCedar(t *testing.T) {
	t.Parallel()

	fileRule := lsm.PolicyRule{Action: lsm.PolicyAllow, Operation: lsm.OpOpen}
	pathFile := "/etc/passwd"
	copy(fileRule.Path[:], pathFile)
	fileRule.PathLen = int32(len(pathFile))

	dirRule := lsm.PolicyRule{Action: lsm.PolicyAllow, Operation: lsm.OpOpen, IsDirectory: 1}
	pathDir := "/var/tmp/"
	copy(dirRule.Path[:], pathDir)
	dirRule.PathLen = int32(len(pathDir))

	connectRule := lsm.PolicyRule{Action: lsm.PolicyDeny, Operation: lsm.OpConnect}
	host := "*.example.com"
	copy(connectRule.Hostname[:], host)
	connectRule.HostnameLen = int32(len(host))

	policies := &lsm.PolicySet{
		Open:                   []lsm.PolicyRule{fileRule, dirRule},
		Connect:                []lsm.PolicyRule{connectRule},
		ConnectDefaultAllow:    true,
		ConnectDefaultExplicit: true,
	}

	cedar := PolicySetToCedar(policies)

	expected := `permit(
    principal,
    action == Action::"FileOpen",
    resource == File::"/etc/passwd"
);

permit(
    principal,
    action == Action::"FileOpen",
    resource == Dir::"/var/tmp/"
);

permit(
    principal,
    action == Action::"NetworkConnect",
    resource == Host::"*"
);

forbid(
    principal,
    action == Action::"NetworkConnect",
    resource == Host::"*.example.com"
);
`

	if cedar != expected {
		t.Fatalf("unexpected cedar output:\nwant:\n%s\ngot:\n%s", expected, cedar)
	}
}

func TestPolicySetToCedarDeduplicatesEquivalentRules(t *testing.T) {
	t.Parallel()

	rule := lsm.PolicyRule{Action: lsm.PolicyAllow, Operation: lsm.OpOpen}
	path := "/etc/passwd"
	copy(rule.Path[:], path)
	rule.PathLen = int32(len(path))

	policies := &lsm.PolicySet{Open: []lsm.PolicyRule{rule, rule}}
	cedar := PolicySetToCedar(policies)
	if got := strings.Count(cedar, "FileOpen"); got != 1 {
		t.Fatalf("expected one deduplicated rule, got %d:\n%s", got, cedar)
	}
}
