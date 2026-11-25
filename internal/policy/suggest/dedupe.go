package suggest

import (
	"sort"
	"strings"
)

// Deduplicate collapses suggestions that describe the same policy. Identity is
// based on the policy's semantics (Kind plus canonical Cedar), not on the
// serialized order of objects, the producer that observed it, or presentation
// details such as whitespace. Evidence from every duplicate is retained in
// PolicyRefs so callers can still explain where the suggestion came from.
//
// Suggestions that merely share a Kind but describe different policies are
// intentionally left separate.
func Deduplicate(items []Suggestion) []Suggestion {
	byIdentity := make(map[string]*Suggestion, len(items))
	order := make([]string, 0, len(items))

	for _, item := range items {
		identity := SemanticIdentity(item)
		if existing, ok := byIdentity[identity]; ok {
			mergeSuggestion(existing, item)
			continue
		}
		clone := cloneSuggestion(item)
		byIdentity[identity] = &clone
		order = append(order, identity)
	}

	out := make([]Suggestion, 0, len(order))
	for _, identity := range order {
		out = append(out, *byIdentity[identity])
	}
	return out
}

// DeduplicateSuggestions is an alias for Deduplicate.
func DeduplicateSuggestions(items []Suggestion) []Suggestion {
	return Deduplicate(items)
}

// Dedupe is a short alias for Deduplicate.
func Dedupe(items []Suggestion) []Suggestion {
	return Deduplicate(items)
}

// DedupeSuggestions is a short alias for DeduplicateSuggestions.
func DedupeSuggestions(items []Suggestion) []Suggestion {
	return Deduplicate(items)
}

// Deduplicated returns a copy of the result with semantic duplicates removed.
func (r Result) Deduplicated() Result {
	return Result{Suggestions: Deduplicate(r.Suggestions)}
}

// SemanticIdentity returns a stable key for the policy represented by s.
// Source/provenance information is deliberately excluded: two producers that
// observed the same policy should collapse into one suggestion whose
// PolicyRefs retain both sources.
func SemanticIdentity(s Suggestion) string {
	var b strings.Builder
	b.WriteString("kind=")
	b.WriteString(string(s.Kind))

	if cedar := strings.TrimSpace(s.ProposedCedar); cedar != "" {
		b.WriteString("\ncedar=")
		b.WriteString(CanonicalCedarIdentity(cedar))
		writeSemanticMetadata(&b, s.Metadata)
		return b.String()
	}

	// Workflow and other non-Cedar suggestions need a stable fallback. Prefer
	// the mined pattern over the cluster summary because summaries contain
	// cluster numbers that vary with input enumeration order.
	if pattern := strings.TrimSpace(s.Metadata["top_pattern"]); pattern != "" {
		b.WriteString("\npattern=")
		b.WriteString(normalizeIdentityText(pattern))
	} else {
		b.WriteString("\nsummary=")
		b.WriteString(normalizeIdentityText(s.Summary))
	}

	writeSemanticMetadata(&b, s.Metadata)

	// Evidence targets are part of a non-Cedar suggestion's meaning, but the
	// producer identity is not: suggestions from different sources with the
	// same target should collapse, while genuinely different targets stay
	// distinct.
	refs := make([]string, 0, len(s.PolicyRefs))
	for _, ref := range s.PolicyRefs {
		refs = append(refs, strings.Join([]string{
			normalizeIdentityText(ref.Effect),
			normalizeIdentityText(ref.Operation),
			normalizeIdentityText(ref.Target),
		}, "\x1f"))
	}
	sort.Strings(refs)
	if len(refs) > 0 {
		b.WriteString("\nrefs=")
		b.WriteString(strings.Join(refs, "\x1e"))
	}
	return b.String()
}

// IdentityKey is an alias for SemanticIdentity.
func IdentityKey(s Suggestion) string {
	return SemanticIdentity(s)
}

// CanonicalIdentity is an alias for SemanticIdentity.
func CanonicalIdentity(s Suggestion) string {
	return SemanticIdentity(s)
}

func writeSemanticMetadata(b *strings.Builder, metadata map[string]string) {
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		if isVolatileSuggestionMetadata(key) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		b.WriteString("\nmeta:")
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(normalizeIdentityText(metadata[key]))
	}
}

func isVolatileSuggestionMetadata(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "cluster_id", "session_count", "principal_count", "coverage_score",
		"recency_score", "confidence", "psi", "drift_flag", "support_sessions",
		"top_support", "top_pattern", "source", "sources", "origin", "producer":
		return true
	default:
		return false
	}
}

func normalizeIdentityText(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func cloneSuggestion(item Suggestion) Suggestion {
	clone := item
	clone.PolicyRefs = normalizePolicyReferences(item.PolicyRefs)
	if item.Metadata != nil {
		clone.Metadata = make(map[string]string, len(item.Metadata))
		for key, value := range item.Metadata {
			clone.Metadata[key] = value
		}
	}
	return clone
}

func mergeSuggestion(dst *Suggestion, src Suggestion) {
	dst.PolicyRefs = normalizePolicyReferences(mergePolicyReferences(dst.PolicyRefs, src.PolicyRefs))
	if src.PolicyCount > dst.PolicyCount {
		dst.PolicyCount = src.PolicyCount
	}
	if src.Confidence > dst.Confidence {
		dst.Confidence = src.Confidence
	}
	if strings.TrimSpace(dst.Summary) == "" {
		dst.Summary = src.Summary
	}
	if strings.TrimSpace(dst.ProposedCedar) == "" {
		dst.ProposedCedar = src.ProposedCedar
	}
	if dst.Metadata == nil && len(src.Metadata) > 0 {
		dst.Metadata = make(map[string]string, len(src.Metadata))
	}
	for key, value := range src.Metadata {
		if _, exists := dst.Metadata[key]; !exists {
			dst.Metadata[key] = value
		}
	}
}

func normalizePolicyReferences(refs []PolicyReference) []PolicyReference {
	refs = mergePolicyReferences(nil, refs)
	sort.SliceStable(refs, func(i, j int) bool {
		return policyReferenceKey(refs[i]) < policyReferenceKey(refs[j])
	})
	return refs
}

func mergePolicyReferences(base, extra []PolicyReference) []PolicyReference {
	out := clonePolicyReferences(base)
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, ref := range out {
		seen[policyReferenceKey(ref)] = struct{}{}
	}
	for _, ref := range extra {
		key := policyReferenceKey(ref)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, clonePolicyReference(ref))
	}
	return out
}

func clonePolicyReferences(refs []PolicyReference) []PolicyReference {
	out := make([]PolicyReference, 0, len(refs))
	for _, ref := range refs {
		out = append(out, clonePolicyReference(ref))
	}
	return out
}

func clonePolicyReference(ref PolicyReference) PolicyReference {
	if ref.Metadata != nil {
		metadata := make(map[string]string, len(ref.Metadata))
		for key, value := range ref.Metadata {
			metadata[key] = value
		}
		ref.Metadata = metadata
	}
	return ref
}

func policyReferenceKey(ref PolicyReference) string {
	return strings.Join([]string{
		ref.Effect,
		ref.Operation,
		ref.Target,
		ref.Source,
		canonicalStringMap(ref.Metadata),
	}, "\x00")
}

func canonicalStringMap(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+normalizeIdentityText(values[key]))
	}
	return strings.Join(parts, "\x1f")
}
