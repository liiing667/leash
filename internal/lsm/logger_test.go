package lsm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type captureBroadcaster struct {
	entries []string
}

func (c *captureBroadcaster) BroadcastLog(entry string) {
	c.entries = append(c.entries, entry)
}

// When the on-disk write fails, the audit event must still reach the
// broadcaster (and therefore the public event spool) so the decision that
// follows the Write call leaves recoverable evidence.
func TestSharedLoggerBroadcastsDespiteFileWriteFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logger, err := NewSharedLogger(filepath.Join(dir, "events.log"))
	if err != nil {
		t.Fatalf("NewSharedLogger: %v", err)
	}

	broadcaster := &captureBroadcaster{}
	logger.SetBroadcaster(broadcaster)

	// Force subsequent file writes to fail.
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = logger.Write(`event=net.send decision=denied`)
	if err == nil {
		t.Fatalf("expected write error after closing the log file")
	}
	if len(broadcaster.entries) != 1 {
		t.Fatalf("expected audit event to reach the spool despite file failure, got %d broadcasts", len(broadcaster.entries))
	}
	if broadcaster.entries[0] != "event=net.send decision=denied" {
		t.Fatalf("unexpected broadcast entry: %q", broadcaster.entries[0])
	}
}

// Normal path: the event is broadcast and persisted, and previously written
// (legitimate old) events remain in the log.
func TestSharedLoggerBroadcastsAndPreservesExistingEvents(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "events.log")
	logger, err := NewSharedLogger(path)
	if err != nil {
		t.Fatalf("NewSharedLogger: %v", err)
	}
	defer logger.Close()

	broadcaster := &captureBroadcaster{}
	logger.SetBroadcaster(broadcaster)

	if err := logger.Write(`event=net.send decision=allowed`); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := logger.Write(`event=file.open decision=denied`); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(broadcaster.entries) != 2 {
		t.Fatalf("expected 2 broadcasts, got %d", len(broadcaster.entries))
	}
	for _, entry := range broadcaster.entries {
		if strings.HasSuffix(entry, "\n") {
			t.Fatalf("broadcast entry must not carry a trailing newline: %q", entry)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "event=net.send decision=allowed\n") {
		t.Fatalf("log file missing first event: %q", content)
	}
	if !strings.Contains(content, "event=file.open decision=denied\n") {
		t.Fatalf("log file missing second event: %q", content)
	}
}

// Empty spool: with no broadcaster and no log file configured, Write is a
// no-op that still succeeds.
func TestSharedLoggerWriteWithoutBroadcasterOrFile(t *testing.T) {
	t.Parallel()

	logger, err := NewSharedLogger("")
	if err != nil {
		t.Fatalf("NewSharedLogger: %v", err)
	}
	if err := logger.Write(`event=net.send decision=allowed`); err != nil {
		t.Fatalf("Write without broadcaster or file: %v", err)
	}

	var nilLogger *SharedLogger
	if err := nilLogger.Write("event=x"); err == nil {
		t.Fatalf("expected error from nil logger")
	}
}
