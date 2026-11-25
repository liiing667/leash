// Package policygen implements recoverable, content-addressed policy
// generations.
//
// A policy generation is a complete, validated Cedar document. Every public
// policy write and every on-disk consumer only ever observes a generation that
// was persisted in full, so a crash or a post-processing failure can never
// leave the daemon with a partially applied policy: on cold start the last
// fully committed generation is restored, never an older or mixed one.
//
// Layout under the leash state directory:
//
//	policy-generations/
//	  gen-<sha256>.cedar   immutable, fsync'd generation objects
//	  current              small pointer file naming the committed generation
//	cedar-runtime.cedar    legacy runtime snapshot (kept in sync for older builds)
//
// The operator-facing canonical Cedar file (e.g. /cfg/leash.cedar) is replaced
// atomically as part of the same commit. Identical content maps to the same
// generation id, which makes re-writing the same policy an idempotent no-op
// rather than a new generation.
package policygen

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// generationsDir is the directory holding immutable generation objects.
	generationsDir = "policy-generations"
	// currentName is the pointer file recording the committed generation id.
	currentName = "current"
	// legacyRuntimeName is the pre-generation runtime snapshot kept for older
	// daemons that still cold-start from it.
	legacyRuntimeName = "cedar-runtime.cedar"
	// genPrefix names generation object files.
	genPrefix = "gen-"
	genSuffix = ".cedar"
)

// Store persists complete policy generations under a leash state directory.
// The zero value is not usable; construct one with New.
type Store struct {
	stateDir string
	// genDir is where immutable generation objects live.
	genDir string
	// canonicalPath is the operator-facing Cedar file replaced on each commit.
	// It may be empty when no canonical path is configured.
	canonicalPath string
}

// New creates a Store rooted at stateDir (typically LEASH_DIR) that also keeps
// canonicalPath in sync. canonicalPath may be empty. Directories are created
// lazily on first commit.
func New(stateDir, canonicalPath string) (*Store, error) {
	dir := strings.TrimSpace(stateDir)
	if dir == "" {
		return nil, errors.New("policy generation state directory is required")
	}
	return &Store{
		stateDir:      dir,
		genDir:        filepath.Join(dir, generationsDir),
		canonicalPath: strings.TrimSpace(canonicalPath),
	}, nil
}

// Generation identifies a persisted, content-addressed policy generation.
type Generation struct {
	// ID is the deterministic content hash of the Cedar document.
	ID string
	// Cedar is the complete Cedar source of the generation.
	Cedar string
}

// IDFor returns the generation id that cedar would have if committed.
func IDFor(cedar string) string {
	sum := sha256.Sum256([]byte(cedar))
	return genPrefix + hex.EncodeToString(sum[:]) + genSuffix
}

func (s *Store) genPath(id string) string {
	return filepath.Join(s.genDir, id)
}

func (s *Store) currentPath() string {
	return filepath.Join(s.genDir, currentName)
}

func (s *Store) legacyRuntimePath() string {
	return filepath.Join(s.stateDir, legacyRuntimeName)
}

// atomicWriteFile writes data to path via a temp file in the same directory,
// fsyncs the file and (best effort) the directory, then renames it into place.
// Readers therefore never observe a partially written file.
func atomicWriteFile(dir, path string, data []byte, perm os.FileMode) (err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write %q: %w", path, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("fsync %q: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close %q: %w", path, err)
	}
	if err = os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("chmod %q: %w", path, err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename into %q: %w", path, err)
	}
	syncDir(dir)
	return nil
}

// syncDir best-effort fsyncs a directory so a rename is durable. Failures are
// ignored on platforms or filesystems where directory fsync is unsupported.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}

// Commit durably persists cedar as a complete generation and atomically marks
// it current. The canonical Cedar file (when configured) and the legacy
// runtime snapshot are replaced with the same content as part of the commit so
// file watchers and older builds only ever see a full document.
//
// Commit is idempotent: when cedar matches the currently committed generation
// no new generation is published and changed is false.
func (s *Store) Commit(cedar string) (gen Generation, changed bool, err error) {
	cedar = strings.TrimSpace(cedar)
	if cedar == "" {
		return Generation{}, false, errors.New("refusing to commit an empty policy generation")
	}

	id := IDFor(cedar)
	data := []byte(cedar + "\n")

	// Fast path: identical generation already committed. Re-publish derived
	// files only when missing or stale, then report no change so callers skip
	// redundant runtime churn.
	if current, curErr := s.currentFromPointer(); curErr == nil && current.ID == id {
		if err := s.syncDerived(data); err != nil {
			return Generation{}, false, err
		}
		return Generation{ID: id, Cedar: current.Cedar}, false, nil
	}

	// 1. Persist the immutable generation object in full first.
	if err := atomicWriteFile(s.genDir, s.genPath(id), data, 0o644); err != nil {
		return Generation{}, false, fmt.Errorf("persist policy generation: %w", err)
	}

	// 2. Publish the canonical file and legacy snapshot from the same bytes.
	if err := s.syncDerived(data); err != nil {
		return Generation{}, false, err
	}

	// 3. Atomically flip the current pointer. Until this rename succeeds the
	// previous generation remains the committed, restorable one.
	if err := atomicWriteFile(s.genDir, s.currentPath(), []byte(id+"\n"), 0o644); err != nil {
		return Generation{}, false, fmt.Errorf("publish current generation pointer: %w", err)
	}

	return Generation{ID: id, Cedar: cedar}, true, nil
}

// syncDerived rewrites the operator-facing canonical file and legacy runtime
// snapshot with data, both atomically.
func (s *Store) syncDerived(data []byte) error {
	if path := s.canonicalPath; path != "" {
		dir := filepath.Dir(path)
		if dir == "" {
			dir = "."
		}
		if err := atomicWriteFile(dir, path, data, 0o644); err != nil {
			return fmt.Errorf("publish canonical policy: %w", err)
		}
	}
	if err := atomicWriteFile(s.stateDir, s.legacyRuntimePath(), data, 0o644); err != nil {
		return fmt.Errorf("sync runtime snapshot: %w", err)
	}
	return nil
}

// Current returns the last fully committed generation.
//
// Recovery preserves compatibility with deployments predating generations:
//  1. The current generation pointer plus its verified immutable object.
//  2. The canonical operator Cedar file (when configured).
//  3. The legacy cedar-runtime snapshot.
//
// A torn pointer write (missing or corrupt object) is not trusted and falls
// through to the legacy files.
func (s *Store) Current() (Generation, error) {
	if gen, err := s.currentFromPointer(); err == nil {
		return gen, nil
	}

	if gen, err := s.loadFromFile(s.canonicalPath); err == nil {
		return gen, nil
	}

	if gen, err := s.loadFromFile(s.legacyRuntimePath()); err == nil {
		return gen, nil
	}

	return Generation{}, fs.ErrNotExist
}

func (s *Store) currentFromPointer() (Generation, error) {
	raw, err := os.ReadFile(s.currentPath())
	if err != nil {
		return Generation{}, err
	}
	id := strings.TrimSpace(string(raw))
	if id == "" {
		return Generation{}, errors.New("empty current generation pointer")
	}
	return s.loadGeneration(id)
}

func (s *Store) loadGeneration(id string) (Generation, error) {
	if !strings.HasPrefix(id, genPrefix) || !strings.HasSuffix(id, genSuffix) {
		return Generation{}, fmt.Errorf("invalid generation id %q", id)
	}
	// Guard against path traversal in pointer contents.
	if filepath.Base(id) != id {
		return Generation{}, fmt.Errorf("invalid generation id %q", id)
	}
	data, err := os.ReadFile(s.genPath(id))
	if err != nil {
		return Generation{}, err
	}
	cedar := strings.TrimSpace(string(data))
	if cedar == "" {
		return Generation{}, errors.New("generation object is empty")
	}
	if IDFor(cedar) != id {
		return Generation{}, fmt.Errorf("generation object %q failed content verification", id)
	}
	return Generation{ID: id, Cedar: cedar}, nil
}

func (s *Store) loadFromFile(path string) (Generation, error) {
	if strings.TrimSpace(path) == "" {
		return Generation{}, fs.ErrNotExist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Generation{}, err
	}
	cedar := strings.TrimSpace(string(data))
	if cedar == "" {
		return Generation{}, fs.ErrNotExist
	}
	return Generation{ID: IDFor(cedar), Cedar: cedar}, nil
}

// CurrentID returns the id of the committed generation, or "" when none exists.
func (s *Store) CurrentID() string {
	gen, err := s.Current()
	if err != nil {
		return ""
	}
	return gen.ID
}
