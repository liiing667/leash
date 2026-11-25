package policygen

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cedarA = `permit (principal, action == Action::"FileOpen", resource == Dir::"/tmp");`

const cedarB = `forbid (principal, action == Action::"Connect", resource == Host::"example.com");`

func TestCommitPublishesCompleteGeneration(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	canonical := filepath.Join(t.TempDir(), "leash.cedar")
	store, err := New(stateDir, canonical)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	gen, changed, err := store.Commit(cedarA)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !changed {
		t.Fatal("first commit should report a change")
	}
	if gen.ID != IDFor(cedarA) {
		t.Fatalf("generation id mismatch: got %q want %q", gen.ID, IDFor(cedarA))
	}

	// The immutable generation object exists in full.
	objectData, err := os.ReadFile(filepath.Join(stateDir, generationsDir, gen.ID))
	if err != nil {
		t.Fatalf("read generation object: %v", err)
	}
	if strings.TrimSpace(string(objectData)) != strings.TrimSpace(cedarA) {
		t.Fatal("generation object content mismatch")
	}

	// Pointer, canonical file and legacy snapshot all carry the same document.
	pointer, err := os.ReadFile(filepath.Join(stateDir, generationsDir, currentName))
	if err != nil {
		t.Fatalf("read pointer: %v", err)
	}
	if strings.TrimSpace(string(pointer)) != gen.ID {
		t.Fatalf("pointer = %q, want %q", pointer, gen.ID)
	}

	canonicalData, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatalf("read canonical file: %v", err)
	}
	if strings.TrimSpace(string(canonicalData)) != strings.TrimSpace(cedarA) {
		t.Fatal("canonical file content mismatch")
	}

	legacyData, err := os.ReadFile(filepath.Join(stateDir, legacyRuntimeName))
	if err != nil {
		t.Fatalf("read legacy runtime snapshot: %v", err)
	}
	if strings.TrimSpace(string(legacyData)) != strings.TrimSpace(cedarA) {
		t.Fatal("legacy runtime snapshot content mismatch")
	}

	got, err := store.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got.ID != gen.ID || got.Cedar != strings.TrimSpace(cedarA) {
		t.Fatalf("Current = %+v, want generation %q", got, gen.ID)
	}
}

func TestCommitIdempotentForSamePolicy(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	store, err := New(stateDir, filepath.Join(t.TempDir(), "leash.cedar"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	first, changed, err := store.Commit(cedarA)
	if err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	if !changed {
		t.Fatal("first commit should report a change")
	}

	// Whitespace differences normalize to the same generation content.
	second, changed, err := store.Commit("\n\n" + cedarA + "\n")
	if err != nil {
		t.Fatalf("second Commit: %v", err)
	}
	if changed {
		t.Fatal("re-writing the same policy must not publish a new generation")
	}
	if second.ID != first.ID {
		t.Fatalf("idempotent commit changed id: %q != %q", second.ID, first.ID)
	}

	entries, err := os.ReadDir(filepath.Join(stateDir, generationsDir))
	if err != nil {
		t.Fatalf("read generations dir: %v", err)
	}
	objects := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), genPrefix) {
			objects++
		}
	}
	if objects != 1 {
		t.Fatalf("expected exactly one generation object, found %d", objects)
	}
}

func TestCommitRejectsEmptyPolicy(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir(), "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := store.Commit("   "); err == nil {
		t.Fatal("expected error committing empty policy")
	}
}

func TestCurrentRecoversLastCommittedGeneration(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	store, err := New(stateDir, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	genA, _, err := store.Commit(cedarA)
	if err != nil {
		t.Fatalf("commit A: %v", err)
	}
	genB, _, err := store.Commit(cedarB)
	if err != nil {
		t.Fatalf("commit B: %v", err)
	}

	// A brand-new store instance over the same directory cold-starts onto B.
	reopened, err := New(stateDir, "")
	if err != nil {
		t.Fatalf("reopen New: %v", err)
	}
	got, err := reopened.Current()
	if err != nil {
		t.Fatalf("cold Current: %v", err)
	}
	if got.ID != genB.ID {
		t.Fatalf("cold start recovered %q, want latest %q", got.ID, genB.ID)
	}

	// The previous generation object remains available for inspection/rollback.
	if _, err := os.Stat(filepath.Join(stateDir, generationsDir, genA.ID)); err != nil {
		t.Fatalf("previous generation object missing: %v", err)
	}
}

func TestCurrentIgnoresTornPointerAndFallsBackToLegacy(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	store, err := New(stateDir, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gen, _, err := store.Commit(cedarA)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Simulate a crash after the pointer flip but with a missing object: the
	// pointer must not be trusted; recovery falls back to the legacy snapshot.
	if err := os.Remove(filepath.Join(stateDir, generationsDir, gen.ID)); err != nil {
		t.Fatalf("remove generation object: %v", err)
	}

	got, err := store.Current()
	if err != nil {
		t.Fatalf("Current after torn pointer: %v", err)
	}
	if got.Cedar != strings.TrimSpace(cedarA) {
		t.Fatalf("fallback recovery = %q, want legacy cedar", got.Cedar)
	}
	if got.ID != IDFor(cedarA) {
		t.Fatalf("fallback generation id = %q", got.ID)
	}
}

// TestCrashBeforePointerFlipKeepsPreviousGeneration verifies the core
// transactional guarantee: if a new generation object is fully written but the
// process crashes before the current pointer flips, recovery still returns the
// previous complete generation rather than a partial/mixed state.
func TestCrashBeforePointerFlipKeepsPreviousGeneration(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	store, err := New(stateDir, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	genA, _, err := store.Commit(cedarA)
	if err != nil {
		t.Fatalf("commit A: %v", err)
	}

	// Simulate writing generation B's object but crashing before pointer flip.
	bID := IDFor(cedarB)
	if err := os.WriteFile(filepath.Join(stateDir, generationsDir, bID), []byte(cedarB+"\n"), 0o644); err != nil {
		t.Fatalf("write orphan generation: %v", err)
	}

	got, err := store.Current()
	if err != nil {
		t.Fatalf("Current after pre-flip crash: %v", err)
	}
	if got.ID != genA.ID {
		t.Fatalf("recovery = %q, want previous generation %q", got.ID, genA.ID)
	}

	// After a successful re-commit of B, recovery advances to the new generation.
	genB, changed, err := store.Commit(cedarB)
	if err != nil {
		t.Fatalf("re-commit B: %v", err)
	}
	if !changed || genB.ID != bID {
		t.Fatalf("expected B to become current, got changed=%v id=%q", changed, genB.ID)
	}
	got, err = store.Current()
	if err != nil {
		t.Fatalf("Current after re-commit: %v", err)
	}
	if got.ID != bID {
		t.Fatalf("recovery = %q, want %q", got.ID, bID)
	}
}

func TestCurrentRecoversFromLegacyFilesOnly(t *testing.T) {
	t.Parallel()

	t.Run("legacy runtime snapshot", func(t *testing.T) {
		stateDir := t.TempDir()
		// Pre-generation deployment layout: only cedar-runtime.cedar exists.
		if err := os.MkdirAll(stateDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stateDir, legacyRuntimeName), []byte(cedarB), 0o644); err != nil {
			t.Fatal(err)
		}

		store, err := New(stateDir, "")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		got, err := store.Current()
		if err != nil {
			t.Fatalf("Current: %v", err)
		}
		if got.Cedar != strings.TrimSpace(cedarB) {
			t.Fatalf("recovered %q, want legacy cedar", got.Cedar)
		}
	})

	t.Run("canonical file", func(t *testing.T) {
		stateDir := t.TempDir()
		canonical := filepath.Join(t.TempDir(), "leash.cedar")
		if err := os.WriteFile(canonical, []byte(cedarA), 0o644); err != nil {
			t.Fatal(err)
		}

		store, err := New(stateDir, canonical)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		got, err := store.Current()
		if err != nil {
			t.Fatalf("Current: %v", err)
		}
		if got.Cedar != strings.TrimSpace(cedarA) {
			t.Fatalf("recovered %q, want canonical cedar", got.Cedar)
		}
	})
}

func TestCurrentMissingWhenNoState(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir(), filepath.Join(t.TempDir(), "missing.cedar"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := store.Current(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist, got %v", err)
	}
	if id := store.CurrentID(); id != "" {
		t.Fatalf("CurrentID = %q, want empty", id)
	}
}

func TestNewRejectsEmptyStateDir(t *testing.T) {
	t.Parallel()
	if _, err := New("  ", ""); err == nil {
		t.Fatal("expected error for empty state dir")
	}
}

func TestPointerPathTraversalRejected(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	store, err := New(stateDir, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := store.Commit(cedarA); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Corrupt the pointer with a traversal payload.
	pointer := filepath.Join(stateDir, generationsDir, currentName)
	if err := os.WriteFile(pointer, []byte("../etc/passwd\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Recovery must ignore the malicious pointer and fall back to legacy state.
	got, err := store.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got.Cedar != strings.TrimSpace(cedarA) {
		t.Fatalf("recovery = %q, want legacy cedar", got.Cedar)
	}
}
