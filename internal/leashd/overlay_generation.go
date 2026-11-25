package leashd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/strongdm/leash/internal/policy"
)

const (
	runtimeCedarFileName      = "cedar-runtime.cedar"
	overlayStateFileName      = "cedar-runtime.overlay.json"
	overlayGenerationFileName = "cedar-runtime.generation"
	policyGenerationSidecar   = "policy.generation"
	legacyOverlayGenerationV1 = int64(1)
)

// overlayState is the durable commit marker for a runtime overlay. The Cedar
// file remains the recoverable policy body; this marker tells a reopened
// process whether that body is the current generation or a stale/deleted one.
type overlayState struct {
	Version           int    `json:"version"`
	Generation        int64  `json:"generation"`
	OverlayGeneration int64  `json:"overlayGeneration"`
	Active            bool   `json:"active"`
	RuntimeOnly       bool   `json:"runtimeOnly"`
	Mode              string `json:"mode,omitempty"`
	Source            string `json:"source,omitempty"`
	CedarSHA256       string `json:"cedarSha256,omitempty"`
}

func runtimeCedarPath() string {
	return filepath.Join(getLeashDirFromEnv(), runtimeCedarFileName)
}

func overlayStatePath() string {
	return filepath.Join(getLeashDirFromEnv(), overlayStateFileName)
}

func overlayGenerationPath() string {
	return filepath.Join(getLeashDirFromEnv(), overlayGenerationFileName)
}

func cedarDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func canonicalOverlayDigest(cedar string) string {
	cedar = strings.TrimSpace(cedar)
	if statements := extractCedarStatements(cedar); len(statements) > 0 {
		cedar = strings.Join(dedupeCedarStatements(statements), "\n\n")
	}
	return cedarDigest([]byte(cedar))
}

func loadOverlayState() (overlayState, error) {
	var state overlayState
	b, err := os.ReadFile(overlayStatePath())
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(b, &state); err != nil {
		return state, err
	}
	if state.OverlayGeneration == 0 && state.Generation != 0 {
		state.OverlayGeneration = state.Generation
	}
	if state.Generation == 0 && state.OverlayGeneration != 0 {
		state.Generation = state.OverlayGeneration
	}
	return state, nil
}

func loadDurableOverlayGeneration() int64 {
	if state, err := loadOverlayState(); err == nil && state.Generation > 0 {
		return state.Generation
	}
	for _, path := range []string{overlayGenerationPath(), filepath.Join(getLeashDirFromEnv(), policyGenerationSidecar)} {
		if b, err := os.ReadFile(path); err == nil {
			if generation, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && generation > 0 {
				return generation
			}
		}
	}
	return 0
}

func generationFromFile(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	generation, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || generation <= 0 {
		return 0
	}
	return generation
}

// loadPolicyGeneration reads the generation sidecar adjacent to policyPath.
// It accepts the common "<policyPath>.generation" and "<dir>/policy.generation"
// layouts used by policy consumers.
func loadPolicyGeneration(policyPath string) int64 {
	policyPath = strings.TrimSpace(policyPath)
	if policyPath == "" {
		return 0
	}
	if generation := generationFromFile(policyPath + ".generation"); generation > 0 {
		return generation
	}
	return generationFromFile(filepath.Join(filepath.Dir(policyPath), policyGenerationSidecar))
}

func (api *policyAPI) canonicalSidecarPaths() (statePath, generationPath string) {
	path := strings.TrimSpace(api.policyPath)
	if path == "" {
		return "", ""
	}
	return path + ".overlay.json", path + ".generation"
}

func (api *policyAPI) generationPath() string {
	_, generationPath := api.canonicalSidecarPaths()
	return generationPath
}

func (api *policyAPI) loadCanonicalSidecarGeneration() int64 {
	statePath, generationPath := api.canonicalSidecarPaths()
	if statePath != "" {
		if b, err := os.ReadFile(statePath); err == nil {
			var state overlayState
			if json.Unmarshal(b, &state) == nil && state.Generation > 0 {
				return state.Generation
			}
		}
	}
	if generationPath != "" {
		if generation := generationFromFile(generationPath); generation > 0 {
			return generation
		}
	}
	policyPath := strings.TrimSpace(api.policyPath)
	if policyPath == "" {
		return 0
	}
	return loadPolicyGeneration(policyPath)
}

func (api *policyAPI) saveCanonicalSidecars(state overlayState) error {
	statePath, generationPath := api.canonicalSidecarPaths()
	if generationPath != "" {
		if err := atomicWriteFile(generationPath, []byte(strconv.FormatInt(state.Generation, 10)+"\n"), 0o600); err != nil {
			return err
		}
	}
	if statePath != "" {
		b, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return err
		}
		return atomicWriteFile(statePath, append(b, '\n'), 0o600)
	}
	return nil
}

func atomicWriteFile(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".overlay-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func saveOverlayState(state overlayState) error {
	if state.Version == 0 {
		state.Version = 1
	}
	if state.OverlayGeneration == 0 {
		state.OverlayGeneration = state.Generation
	}
	if state.Generation == 0 {
		state.Generation = state.OverlayGeneration
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(overlayStatePath(), append(b, '\n'), 0o600); err != nil {
		return err
	}
	generation := state.Generation
	if generation <= 0 {
		return nil
	}
	return atomicWriteFile(overlayGenerationPath(), []byte(strconv.FormatInt(generation, 10)+"\n"), 0o600)
}

// commitRuntimeOverlay records the current durable runtime overlay. It does not
// own in-memory rule publication; callers must update the Manager first and
// only call this after validation succeeds.
func (api *policyAPI) commitRuntimeOverlay(active, runtimeOnly bool, mode, source, cedar string) (int64, error) {
	api.mu.Lock()
	generation := api.overlayGeneration
	api.overlayGeneration = generation
	api.mu.Unlock()
	if api.mgr != nil {
		if managerGeneration := api.mgr.OverlayGeneration(); managerGeneration > generation {
			generation = managerGeneration
		}
	}
	if durable := loadDurableOverlayGeneration(); durable > generation {
		generation = durable
	}
	if generation <= 0 {
		generation = 1
	}

	if api.mgr != nil {
		api.mgr.SetOverlayGeneration(generation)
	}
	api.mu.Lock()
	api.overlayGeneration = generation
	api.mu.Unlock()

	state := overlayState{
		Version:           1,
		Generation:        generation,
		OverlayGeneration: generation,
		Active:            active,
		RuntimeOnly:       runtimeOnly,
		Mode:              mode,
		Source:            source,
	}
	if active && strings.TrimSpace(cedar) != "" {
		state.CedarSHA256 = canonicalOverlayDigest(cedar)
	}
	if err := saveOverlayState(state); err != nil {
		return generation, err
	}
	if err := api.saveCanonicalSidecars(state); err != nil {
		return generation, err
	}
	if api.mgr != nil {
		api.mgr.SetOverlayIdentity(policy.OverlayInfo{
			Generation:  generation,
			Active:      active,
			RuntimeOnly: runtimeOnly,
			Source:      source,
			Token:       state.CedarSHA256,
		})
	}
	return generation, nil
}

// commitOverlayTombstone publishes the deleted generation and removes the
// stale Cedar body when possible. The tombstone is the authoritative reopen
// marker even if removal fails.
func (api *policyAPI) commitOverlayTombstone(mode, source string) (int64, error) {
	generation, err := api.commitRuntimeOverlay(false, false, mode, source, "")
	if err != nil {
		return generation, err
	}
	if err := os.Remove(runtimeCedarPath()); err != nil && !os.IsNotExist(err) {
		// Do not leave a permissive stale body behind if unlink fails. An
		// empty atomically-renamed file is ignored by the legacy loader.
		if saveErr := saveCedarRuntime(nil); saveErr != nil {
			return generation, saveErr
		}
	}
	return generation, nil
}

func (api *policyAPI) currentOverlayGeneration() int64 {
	api.mu.RLock()
	generation := api.overlayGeneration
	api.mu.RUnlock()
	if api.mgr != nil {
		if managerGeneration := api.mgr.OverlayGeneration(); managerGeneration > generation {
			generation = managerGeneration
		}
	}
	if generation <= 0 {
		generation = loadDurableOverlayGeneration()
	}
	return generation
}

func (api *policyAPI) enforcementModeValue() string {
	if api == nil {
		return ""
	}
	api.mu.RLock()
	defer api.mu.RUnlock()
	return api.mode
}

func (api *policyAPI) publishProxyOverlayGeneration() {
	if api == nil || api.mitmProxy == nil {
		return
	}
	generation := api.currentOverlayGeneration()
	api.mitmProxy.SetPolicyGeneration(generation)
}

func overlayResponseFields(api *policyAPI) map[string]any {
	info := policy.OverlayInfo{}
	if api != nil && api.mgr != nil {
		info = api.mgr.OverlaySnapshot()
	}
	generation := int64(0)
	if api != nil {
		generation = api.currentOverlayGeneration()
	}
	if info.Generation > generation {
		generation = info.Generation
	}
	info.Generation = generation

	mode := ""
	runtimeOnly := info.RuntimeOnly
	if api != nil {
		api.mu.RLock()
		mode = api.mode
		api.mu.RUnlock()
		if strings.EqualFold(mode, "permit-all") {
			runtimeOnly = true
			info.Active = true
		}
	}
	if info.Active {
		// Keep the nested identity consistent with the public mode.
		info.RuntimeOnly = runtimeOnly
	}

	token := info.Token
	if token == "" && generation > 0 {
		token = strconv.FormatInt(generation, 10)
	}
	contentHash := info.Token
	if contentHash == "" && api != nil {
		api.mu.RLock()
		cedar := api.cedarRuntime
		api.mu.RUnlock()
		if strings.TrimSpace(cedar) != "" {
			contentHash = canonicalOverlayDigest(cedar)
		}
	}
	overlay := map[string]any{
		"generation":         generation,
		"overlayGeneration":  generation,
		"overlay_generation": generation,
		"overlayGen":         generation,
		"overlay_gen":        generation,
		"runtimeGeneration":  generation,
		"runtimeGen":         generation,
		"active":             info.Active,
		"overlayActive":      info.Active,
		"runtimeOnly":        runtimeOnly,
		"mode":               mode,
		"source":             info.Source,
		"token":              token,
		"contentHash":        contentHash,
		"cedarSha256":        contentHash,
	}
	return map[string]any{
		"generation":         generation,
		"currentGeneration":  generation,
		"overlayGeneration":  generation,
		"overlay_generation": generation,
		"overlayGen":         generation,
		"overlay_gen":        generation,
		"runtimeGeneration":  generation,
		"runtime_generation": generation,
		"runtimeGen":         generation,
		"activeGeneration":   generation,
		"overlayActive":      info.Active,
		"overlay_active":     info.Active,
		"hasOverlay":         info.Active,
		"runtimeOnly":        runtimeOnly,
		"overlay":            overlay,
		"runtimeOverlay":     overlay,
		"overlaySnapshot":    overlay,
		"contentHash":        contentHash,
		"cedarSha256":        contentHash,
	}
}
