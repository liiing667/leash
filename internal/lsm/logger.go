package lsm

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// LogBroadcaster is an interface for broadcasting log entries
type LogBroadcaster interface {
	BroadcastLog(logEntry string)
}

// SharedLogger provides a single append-only log file with cross-component synchronization.
type SharedLogger struct {
	path        string
	file        *os.File
	mutex       sync.Mutex
	broadcaster LogBroadcaster
}

func NewSharedLogger(path string) (*SharedLogger, error) {
	logger := &SharedLogger{path: path}
	if strings.TrimSpace(path) == "" {
		return logger, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file '%s': %w", path, err)
	}
	logger.file = f
	return logger, nil
}

func (l *SharedLogger) Path() string { return l.path }

// SetBroadcaster sets the log broadcaster for real-time log streaming
func (l *SharedLogger) SetBroadcaster(broadcaster LogBroadcaster) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.broadcaster = broadcaster
}

// Write writes a full log entry line in a thread-safe way.
// Automatically adds a newline if the entry doesn't end with one.
func (l *SharedLogger) Write(entry string) error {
	if l == nil {
		return fmt.Errorf("logger is not initialized")
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Ensure entry ends with newline
	if len(entry) > 0 && entry[len(entry)-1] != '\n' {
		entry += "\n"
	}

	// Broadcast to websocket clients (if broadcaster is set) before touching
	// the disk. The public event spool must carry recoverable evidence of the
	// audit event even when the file write below fails: callers proceed to
	// allow or deny the operation once Write returns, so a disk error must
	// not leave the spool empty.
	if l.broadcaster != nil {
		// Remove the newline for broadcasting
		broadcastEntry := entry
		if len(broadcastEntry) > 0 && broadcastEntry[len(broadcastEntry)-1] == '\n' {
			broadcastEntry = broadcastEntry[:len(broadcastEntry)-1]
		}
		l.broadcaster.BroadcastLog(broadcastEntry)
	}

	// Write to file when configured
	if l.file != nil {
		if _, err := l.file.WriteString(entry); err != nil {
			return err
		}
		return l.file.Sync()
	}
	return nil
}

func (l *SharedLogger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}
