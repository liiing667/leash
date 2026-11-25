package leashd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
	"github.com/strongdm/leash/internal/policy"
	"github.com/strongdm/leash/internal/policygen"
	"github.com/strongdm/leash/internal/proxy"
)

var errInjectedPostFailure = errors.New("injected post-processing failure")

func setupGenerationAPI(t *testing.T) (string, string, *policy.Manager, *http.ServeMux, *policyAPI) {
	t.Helper()

	tmpDir := t.TempDir()
	t.Setenv("LEASH_DIR", tmpDir)
	policyPath := filepath.Join(tmpDir, "policies.cedar")

	mux := http.NewServeMux()
	mgr := policy.NewManager(nil, func(*lsm.PolicySet, []proxy.HeaderRewriteRule) {})
	api := newPolicyAPI(mgr, policyPath, nil, nil, nil)
	api.register(mux)
	return tmpDir, policyPath, mgr, mux, api
}

func postCedar(t *testing.T, mux *http.ServeMux, cedar string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"cedar": cedar})
	req := httptest.NewRequest(http.MethodPost, "/api/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

const generationPolicyA = `permit (principal, action == Action::"NetworkConnect", resource == Host::"allowed.example.com");`

const generationPolicyB = `forbid (principal, action == Action::"NetworkConnect", resource == Host::"blocked.example.com");`

// TestGenerationCommitWritesCompleteGeneration verifies a public write persists
// a full generation object, current pointer, canonical file and legacy snapshot
// carrying identical content.
func TestGenerationCommitWritesCompleteGeneration(t *testing.T) {

	tmpDir, policyPath, _, mux, api := setupGenerationAPI(t)

	// The baseline seed already commits a generation; then write policy A.
	w := postCedar(t, mux, generationPolicyA)
	if w.Code != http.StatusOK {
		t.Fatalf("POST policies returned %d: %s", w.Code, w.Body.String())
	}

	store := api.genStore
	if store == nil {
		t.Fatal("generation store not wired")
	}
	gen, err := store.Current()
	if err != nil {
		t.Fatalf("Current generation: %v", err)
	}
	if gen.ID != policygen.IDFor(generationPolicyA) {
		t.Fatalf("current generation = %q, want %q", gen.ID, policygen.IDFor(generationPolicyA))
	}

	object, err := os.ReadFile(filepath.Join(tmpDir, "policy-generations", gen.ID))
	if err != nil {
		t.Fatalf("generation object missing: %v", err)
	}
	if strings.TrimSpace(string(object)) != strings.TrimSpace(generationPolicyA) {
		t.Fatal("generation object content mismatch")
	}

	canonical, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("canonical file missing: %v", err)
	}
	if strings.TrimSpace(string(canonical)) != strings.TrimSpace(generationPolicyA) {
		t.Fatal("canonical file does not match committed generation")
	}

	legacy, err := os.ReadFile(filepath.Join(tmpDir, "cedar-runtime.cedar"))
	if err != nil {
		t.Fatalf("legacy runtime snapshot missing: %v", err)
	}
	if strings.TrimSpace(string(legacy)) != strings.TrimSpace(generationPolicyA) {
		t.Fatal("legacy snapshot does not match committed generation")
	}
}

// TestGenerationIdempotentSamePolicy verifies writing the same policy twice is
// a no-op: only one generation object exists and the API still returns success.
func TestGenerationIdempotentSamePolicy(t *testing.T) {

	tmpDir, _, _, mux, api := setupGenerationAPI(t)

	first := postCedar(t, mux, generationPolicyA)
	if first.Code != http.StatusOK {
		t.Fatalf("first POST returned %d: %s", first.Code, first.Body.String())
	}

	before := api.genStore.CurrentID()
	objectsBefore := countGenerationObjects(t, tmpDir)

	// Re-submit the same policy (with extra whitespace, which normalizes away).
	second := postCedar(t, mux, "\n"+generationPolicyA+"\n")
	if second.Code != http.StatusOK {
		t.Fatalf("idempotent POST returned %d: %s", second.Code, second.Body.String())
	}

	after := api.genStore.CurrentID()
	if before != after {
		t.Fatalf("same policy created a new generation: %q -> %q", before, after)
	}

	if objectsAfter := countGenerationObjects(t, tmpDir); objectsAfter != objectsBefore {
		t.Fatalf("identical write changed generation object count: before=%d after=%d", objectsBefore, objectsAfter)
	}
}

func countGenerationObjects(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "policy-generations"))
	if err != nil {
		t.Fatalf("read generations dir: %v", err)
	}
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "gen-") {
			count++
		}
	}
	return count
}

// TestGenerationColdStartRecoversLatest verifies a brand-new API instance over
// the same state directory recovers the last committed generation rather than
// reverting to an older policy.
func TestGenerationColdStartRecoversLatest(t *testing.T) {

	_, policyPath, _, mux, _ := setupGenerationAPI(t)

	if w := postCedar(t, mux, generationPolicyA); w.Code != http.StatusOK {
		t.Fatalf("POST A returned %d", w.Code)
	}
	if w := postCedar(t, mux, generationPolicyB); w.Code != http.StatusOK {
		t.Fatalf("POST B returned %d", w.Code)
	}

	// Simulate cold start: new manager and API over the same directories.
	freshMgr := policy.NewManager(nil, func(*lsm.PolicySet, []proxy.HeaderRewriteRule) {})
	freshAPI := newPolicyAPI(freshMgr, policyPath, nil, nil, nil)

	freshAPI.mu.RLock()
	recovered := freshAPI.cedarRuntime
	freshAPI.mu.RUnlock()
	if strings.TrimSpace(recovered) != strings.TrimSpace(generationPolicyB) {
		t.Fatalf("cold start recovered %q, want latest generation %q", recovered, generationPolicyB)
	}

	gen, err := freshAPI.genStore.Current()
	if err != nil {
		t.Fatalf("cold start Current: %v", err)
	}
	if gen.ID != policygen.IDFor(generationPolicyB) {
		t.Fatalf("cold start generation = %q", gen.ID)
	}
}

// TestGenerationRecoversLegacyRuntimeSnapshot verifies deployments that predate
// generations still recover from cedar-runtime.cedar.
func TestGenerationRecoversLegacyRuntimeSnapshot(t *testing.T) {

	tmpDir := t.TempDir()
	t.Setenv("LEASH_DIR", tmpDir)
	if err := os.WriteFile(filepath.Join(tmpDir, "cedar-runtime.cedar"), []byte(generationPolicyA), 0o644); err != nil {
		t.Fatal(err)
	}

	mgr := policy.NewManager(nil, func(*lsm.PolicySet, []proxy.HeaderRewriteRule) {})
	api := newPolicyAPI(mgr, filepath.Join(tmpDir, "policies.cedar"), nil, nil, nil)

	gen, err := api.genStore.Current()
	if err != nil {
		t.Fatalf("legacy recovery Current: %v", err)
	}
	if strings.TrimSpace(gen.Cedar) != strings.TrimSpace(generationPolicyA) {
		t.Fatalf("legacy recovery = %q", gen.Cedar)
	}

	api.mu.RLock()
	restored := api.cedarRuntime
	api.mu.RUnlock()
	if strings.TrimSpace(restored) != strings.TrimSpace(generationPolicyA) {
		t.Fatalf("API did not surface legacy policy, got %q", restored)
	}
}

// TestGenerationRollsBackMemoryWhenPostProcessingFails verifies that when the
// in-memory application fails after the durable generation is committed, the
// API returns an error and every enforcement layer rolls back to the previous
// generation while the new generation remains safely recoverable on disk.
func TestGenerationRollsBackMemoryWhenPostProcessingFails(t *testing.T) {

	_, _, mgr, mux, api := setupGenerationAPI(t)

	// Establish generation A as the committed previous generation (nil LSM
	// manager makes all in-memory applies succeed in tests).
	if w := postCedar(t, mux, generationPolicyA); w.Code != http.StatusOK {
		t.Fatalf("POST A returned %d: %s", w.Code, w.Body.String())
	}
	prevGen := api.genStore.CurrentID()

	fileBefore, httpBefore, runtimeBefore, runtimeHTTPBefore := mgr.Snapshot()

	// Drive the same transaction the HTTP handlers use, but with a failing
	// post-processing step to simulate an LSM/proxy failure after durable commit.
	_, err := api.commitPolicyTransaction(generationPolicyB, "test-failure", false, func() error {
		return errInjectedPostFailure
	})
	if err == nil {
		t.Fatal("expected transaction error when post-processing fails")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected rollback error, got %v", err)
	}

	// In-memory layers must be restored to the previous generation.
	fileAfter, httpAfter, runtimeAfter, runtimeHTTPAfter := mgr.Snapshot()
	if !policySetsEqual(fileBefore, fileAfter) || !httpRulesEqual(httpBefore, httpAfter) {
		t.Fatal("file layer was not rolled back after post-processing failure")
	}
	if !policySetsEqual(runtimeBefore, runtimeAfter) || !httpRulesEqual(runtimeHTTPBefore, runtimeHTTPAfter) {
		t.Fatal("runtime layer was not rolled back after post-processing failure")
	}

	api.mu.RLock()
	cedarAfter := api.cedarRuntime
	api.mu.RUnlock()
	if strings.TrimSpace(cedarAfter) != strings.TrimSpace(generationPolicyA) {
		t.Fatalf("operative Cedar = %q, want previous generation A", cedarAfter)
	}

	// The durable generation B is still fully committed and recoverable, so a
	// cold start resumes a complete policy rather than a mixed/partial one.
	gen, err := api.genStore.Current()
	if err != nil {
		t.Fatalf("Current after failed apply: %v", err)
	}
	if gen.ID != policygen.IDFor(generationPolicyB) {
		t.Fatalf("durable generation = %q, want B", gen.ID)
	}
	if gen.ID == prevGen {
		t.Fatal("expected new generation B to remain committed on disk")
	}

	// End-to-end closure of the original bug: a fresh daemon over the same
	// state directory cold-starts onto the complete generation B. It must never
	// resurrect a mixed state or silently revert to the previous generation's
	// enforcement while presenting B.
	freshMgr := policy.NewManager(nil, func(*lsm.PolicySet, []proxy.HeaderRewriteRule) {})
	freshAPI := newPolicyAPI(freshMgr, api.policyPath, nil, nil, nil)
	freshGen, err := freshAPI.genStore.Current()
	if err != nil {
		t.Fatalf("cold start Current: %v", err)
	}
	if freshGen.ID != policygen.IDFor(generationPolicyB) {
		t.Fatalf("cold start recovered %q, want complete generation B", freshGen.ID)
	}
	freshAPI.mu.RLock()
	recoveredCedar := freshAPI.cedarRuntime
	freshAPI.mu.RUnlock()
	if strings.TrimSpace(recoveredCedar) != strings.TrimSpace(generationPolicyB) {
		t.Fatalf("cold start cedar = %q, want B", recoveredCedar)
	}
}

// httpRulesEqual compares header rewrite rules by their stable string form.
func httpRulesEqual(a, b []proxy.HeaderRewriteRule) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, r := range a {
		seen[r.String()]++
	}
	for _, r := range b {
		seen[r.String()]--
		if seen[r.String()] < 0 {
			return false
		}
	}
	return true
}
