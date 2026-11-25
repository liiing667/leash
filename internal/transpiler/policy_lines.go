package transpiler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/proxy"
)

func cloneAndSortPolicyRules(policies *lsm.PolicySet) (openRules, execRules, connectRules []lsm.PolicyRule) {
	openRules = append([]lsm.PolicyRule(nil), policies.Open...)
	execRules = append([]lsm.PolicyRule(nil), policies.Exec...)
	connectRules = append([]lsm.PolicyRule(nil), policies.Connect...)

	sort.SliceStable(openRules, func(i, j int) bool {
		if openRules[i].PathLen == openRules[j].PathLen {
			return openRules[i].String() < openRules[j].String()
		}
		return openRules[i].PathLen > openRules[j].PathLen
	})

	sort.SliceStable(execRules, func(i, j int) bool {
		if execRules[i].PathLen == execRules[j].PathLen {
			return execRules[i].String() < execRules[j].String()
		}
		return execRules[i].PathLen > execRules[j].PathLen
	})

	sort.SliceStable(connectRules, func(i, j int) bool {
		if connectRules[i].HostnameLen == connectRules[j].HostnameLen {
			return connectRules[i].String() < connectRules[j].String()
		}
		return connectRules[i].HostnameLen > connectRules[j].HostnameLen
	})

	// Grouping or ingesting the same source through different object orders can
	// produce identical rule entries. They describe one policy, so publishing
	// both would only duplicate Cedar statements and confuse persistence.
	openRules = dedupePolicyRules(openRules)
	execRules = dedupePolicyRules(execRules)
	connectRules = dedupePolicyRules(connectRules)

	return
}

func dedupePolicyRules(rules []lsm.PolicyRule) []lsm.PolicyRule {
	seen := make(map[string]struct{}, len(rules))
	out := make([]lsm.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		key := policyRuleIdentity(rule)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, rule)
	}
	return out
}

func policyRuleIdentity(rule lsm.PolicyRule) string {
	var args []string
	for i := int32(0); i < rule.ArgCount && i < int32(len(rule.Args)); i++ {
		length := rule.ArgLens[i]
		if length < 0 {
			length = 0
		}
		if length > int32(len(rule.Args[i])) {
			length = int32(len(rule.Args[i]))
		}
		args = append(args, string(rule.Args[i][:length]))
	}
	pathLen := rule.PathLen
	if pathLen < 0 {
		pathLen = 0
	}
	if pathLen > int32(len(rule.Path)) {
		pathLen = int32(len(rule.Path))
	}
	hostnameLen := rule.HostnameLen
	if hostnameLen < 0 {
		hostnameLen = 0
	}
	if hostnameLen > int32(len(rule.Hostname)) {
		hostnameLen = int32(len(rule.Hostname))
	}
	return fmt.Sprintf("%d|%d|%s|%d|%d|%d|%d|%d|%s|%d|%s",
		rule.Action,
		rule.Operation,
		string(rule.Path[:pathLen]),
		rule.IsDirectory,
		rule.ArgCount,
		rule.HasWildcard,
		rule.DestIP,
		rule.DestPort,
		string(rule.Hostname[:hostnameLen]),
		rule.IsWildcard,
		strings.Join(args, "\x00"),
	)
}

func PolicySetToLines(policies *lsm.PolicySet, httpRules []proxy.HeaderRewriteRule) []string {
	if policies == nil {
		policies = &lsm.PolicySet{}
	}

	openRules, execRules, connectRules := cloneAndSortPolicyRules(policies)
	rewriteRules := append([]proxy.HeaderRewriteRule(nil), httpRules...)

	sort.SliceStable(rewriteRules, func(i, j int) bool {
		return rewriteRules[i].String() < rewriteRules[j].String()
	})

	total := len(openRules) + len(execRules) + len(connectRules) + len(rewriteRules)
	if policies.ConnectDefaultExplicit {
		total++
	}
	if total == 0 {
		return nil
	}

	lines := make([]string, 0, total)

	for _, rule := range openRules {
		lines = append(lines, rule.String())
	}

	for _, rule := range execRules {
		lines = append(lines, rule.String())
	}

	if policies.ConnectDefaultExplicit {
		if policies.ConnectDefaultAllow {
			lines = append(lines, "default net.send allow")
		} else {
			lines = append(lines, "default net.send deny")
		}
	}

	for _, rule := range connectRules {
		lines = append(lines, rule.String())
	}

	for _, rule := range rewriteRules {
		lines = append(lines, rule.String())
	}

	return lines
}
