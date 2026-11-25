package leashd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrPolicyGenerationConflict indicates that an update was based on a stale
// policy generation.
var ErrPolicyGenerationConflict = errors.New("policy generation conflict")

func bytesTrimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

type generationPrecondition struct {
	generation int64
	hasGen     bool
	tokens     []string
	wildcard   bool
}

func parseGenerationPrecondition(r *http.Request, body []byte) (generationPrecondition, error) {
	var pre generationPrecondition

	addValue := func(raw string) error {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil
		}
		if raw == "*" {
			pre.wildcard = true
			return nil
		}
		raw = strings.TrimPrefix(raw, "W/")
		raw = strings.TrimSpace(raw)
		raw = strings.Trim(raw, `"`)
		if value, err := strconv.ParseInt(raw, 10, 64); err == nil {
			pre.generation = value
			pre.hasGen = true
			return nil
		}
		if raw != "" {
			pre.tokens = append(pre.tokens, raw)
		}
		return nil
	}
	addRaw := func(raw json.RawMessage) error {
		trimmed := bytesTrimSpace(raw)
		if len(trimmed) == 0 || string(trimmed) == "null" {
			return nil
		}
		var number int64
		if err := json.Unmarshal(trimmed, &number); err == nil {
			pre.generation = number
			pre.hasGen = true
			return nil
		}
		var text string
		if err := json.Unmarshal(trimmed, &text); err == nil {
			for _, part := range strings.Split(text, ",") {
				if err := addValue(part); err != nil {
					return err
				}
			}
			return nil
		}
		return fmt.Errorf("invalid policy generation")
	}

	// JSON field aliases. Keeping all accepted spellings here avoids coupling
	// clients to one wire name while still requiring an exact match when one is
	// supplied.
	if len(body) > 0 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err == nil {
			for _, key := range []string{
				"generation",
				"expectedGeneration",
				"expected_generation",
				"readGeneration",
				"read_generation",
				"observedGeneration",
				"observed_generation",
				"snapshotGeneration",
				"snapshot_generation",
				"lastReadGeneration",
				"baseGeneration",
				"base_generation",
				"policyGeneration",
				"policy_generation",
				"version",
				"policyVersion",
				"policy_version",
				"expectedVersion",
				"expected_version",
				"revision",
				"etag",
				"eTag",
				"ETag",
				"expectedETag",
				"expectedEtag",
			} {
				if raw, ok := fields[key]; ok {
					if err := addRaw(raw); err != nil {
						return pre, err
					}
					break
				}
			}

			// Accept {"expected": {"generation": N}} and {"base": {"generation": N}}.
			for _, key := range []string{"expected", "base", "precondition"} {
				if raw, ok := fields[key]; ok {
					var nested map[string]json.RawMessage
					if err := json.Unmarshal(raw, &nested); err == nil {
						for _, nestedKey := range []string{"generation", "expectedGeneration", "version", "revision"} {
							if nestedRaw, ok := nested[nestedKey]; ok {
								if err := addRaw(nestedRaw); err != nil {
									return pre, err
								}
							}
						}
					}
				}
			}
		}
	}

	// Query aliases are useful to test harnesses and non-browser clients.
	query := r.URL.Query()
	for _, key := range []string{"generation", "expectedGeneration", "expected_generation", "baseGeneration", "version"} {
		if values, ok := query[key]; ok && len(values) > 0 {
			if err := addValue(values[0]); err != nil {
				return pre, err
			}
		}
	}

	// Explicit generation headers.
	for _, header := range []string{
		"X-Policy-Generation",
		"X-Generation",
		"X-Expected-Generation",
		"X-Expected-Policy-Generation",
		"X-Base-Generation",
		"X-Version",
		"X-Expected-Version",
	} {
		if value := strings.TrimSpace(r.Header.Get(header)); value != "" {
			if err := addValue(value); err != nil {
				return pre, err
			}
		}
	}

	// Standard optimistic-concurrency header. ETags may be comma separated.
	if ifMatch := strings.TrimSpace(r.Header.Get("If-Match")); ifMatch != "" {
		for _, candidate := range strings.Split(ifMatch, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "*" {
				pre.wildcard = true
				continue
			}
			candidate = strings.TrimPrefix(candidate, "W/")
			candidate = strings.TrimSpace(candidate)
			if err := addValue(candidate); err != nil {
				return pre, err
			}
		}
	}

	return pre, nil
}

func (p generationPrecondition) required() bool {
	return p.wildcard || p.hasGen || len(p.tokens) > 0
}

func (p generationPrecondition) matches(generation int64, cedar string) bool {
	if !p.required() {
		return true
	}
	if p.wildcard {
		return true
	}
	if p.hasGen && p.generation != generation {
		return false
	}
	if len(p.tokens) > 0 {
		token := policyGenerationToken(cedar)
		etag := policyETag(cedar)
		quoted := strings.Trim(etag, `"`)
		matched := false
		for _, candidate := range p.tokens {
			candidate = strings.Trim(strings.TrimSpace(candidate), `"`)
			if candidate == token || candidate == quoted {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func canonicalPolicyGenerationCedar(cedar string) string {
	statements := dedupeCedarStatements(extractCedarStatements(cedar))
	return strings.Join(statements, "\n\n")
}

func policyGenerationToken(cedar string) string {
	sum := sha256.Sum256([]byte(canonicalPolicyGenerationCedar(cedar)))
	return hex.EncodeToString(sum[:])
}

func policyETag(cedar string) string {
	return `"` + policyGenerationToken(cedar) + `"`
}

func generationETag(generation int64) string {
	return `"` + strconv.FormatInt(generation, 10) + `"`
}

func (api *policyAPI) currentPolicyGeneration() int64 {
	api.mu.RLock()
	defer api.mu.RUnlock()
	return api.generation
}

// Generation exposes the current optimistic-concurrency generation to
// in-package and future exported callers.
func (api *policyAPI) Generation() int64 {
	return api.currentPolicyGeneration()
}

// CurrentGeneration is an explicitly named accessor for the same generation.
func (api *policyAPI) CurrentGeneration() int64 {
	return api.currentPolicyGeneration()
}

func (api *policyAPI) enforcementModeValue() string {
	api.mu.RLock()
	defer api.mu.RUnlock()
	return api.mode
}

func (api *policyAPI) advancePolicyGeneration() int64 {
	api.mu.Lock()
	api.generation++
	generation := api.generation
	api.mu.Unlock()
	api.savePolicyGeneration(generation)
	return generation
}

func (api *policyAPI) generationPath() string {
	path := strings.TrimSpace(api.policyPath)
	if path == "" {
		return ""
	}
	return path + ".generation"
}

func loadPolicyGeneration(policyPath string) int64 {
	path := strings.TrimSpace(policyPath)
	if path == "" {
		return 0
	}
	b, err := os.ReadFile(path + ".generation")
	if err != nil {
		// Also tolerate a file located in the policy directory for callers that
		// prefer metadata beside, rather than suffixing, the canonical file.
		b, err = os.ReadFile(filepath.Join(filepath.Dir(path), "policy.generation"))
		if err != nil {
			return 0
		}
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || value < 0 {
		return 0
	}
	return value
}

func (api *policyAPI) savePolicyGeneration(generation int64) {
	path := api.generationPath()
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".generation-*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(strconv.FormatInt(generation, 10) + "\n"); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	_ = os.Rename(tmpName, path)
}

func (api *policyAPI) writeGenerationConflict(w http.ResponseWriter, r *http.Request) {
	current := api.currentPolicyGeneration()
	cedar := api.currentCedarSnapshot()
	etag := generationETag(current)
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Policy-Generation", strconv.FormatInt(current, 10))
	w.Header().Set("X-Expected-Policy-Generation", r.Header.Get("X-Policy-Generation"))
	writeJSON(w, http.StatusConflict, map[string]any{
		"error": map[string]any{
			"message":           "policy generation conflict; reload policies and retry",
			"code":              "POLICY_GENERATION_CONFLICT",
			"reason":            "generation_conflict",
			"type":              "generation_conflict",
			"generation":        current,
			"currentGeneration": current,
			"etag":              etag,
		},
		"generation":        current,
		"currentGeneration": current,
		"conflict":          true,
		"etag":              etag,
		"contentEtag":       policyETag(cedar),
	})
}
