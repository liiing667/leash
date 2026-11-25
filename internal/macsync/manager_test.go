package macsync

import (
	"errors"
	"testing"

	"github.com/strongdm/leash/internal/messages"
)

func hello(stableID, sessionID string) *messages.ClientHelloPayload {
	return &messages.ClientHelloPayload{
		Platform:     "darwin",
		Capabilities: []string{"rule-sync"},
		Version:      "test",
		ClientID:     stableID,
		SessionID:    sessionID,
	}
}

func ruleSync(sessionID string, generation uint64) *messages.MacRuleSyncPayload {
	return &messages.MacRuleSyncPayload{
		FileRules: []messages.MacFileRule{
			{ID: "f1", Action: "deny", Executable: "/bin/cat"},
		},
		Version:    "v1",
		SessionID:  sessionID,
		Generation: generation,
	}
}

// A normal rule update from the registered session commits a snapshot bound
// to the client, session and generation.
func TestUpdateRules_CommitsBoundTransaction(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)
	m.RegisterClient("conn-1", hello("client-a", "session-1"))

	snap, err := m.UpdateRules("conn-1", ruleSync("session-1", 1))
	if err != nil {
		t.Fatalf("expected commit, got %v", err)
	}
	if snap.ClientID != "client-a" || snap.SessionID != "session-1" || snap.Generation != 1 {
		t.Fatalf("snapshot not bound correctly: %+v", snap)
	}

	public, ok := m.PublicRuleSnapshot()
	if !ok || public.Generation != 1 || public.ClientID != "client-a" {
		t.Fatalf("public snapshot mismatch: ok=%v snap=%+v", ok, public)
	}
}

// Replayed or out-of-order generations must be rejected without mutating the
// committed state, so a delayed old message can never roll rules backwards.
func TestUpdateRules_RejectsStaleGeneration(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)
	m.RegisterClient("conn-1", hello("client-a", "session-1"))

	if _, err := m.UpdateRules("conn-1", ruleSync("session-1", 2)); err != nil {
		t.Fatalf("initial commit failed: %v", err)
	}

	// Same generation (replay) and older generation must both fail.
	for _, gen := range []uint64{2, 1} {
		_, err := m.UpdateRules("conn-1", ruleSync("session-1", gen))
		var stale *StaleRuleSyncError
		if !errors.As(err, &stale) {
			t.Fatalf("generation %d: expected StaleRuleSyncError, got %v", gen, err)
		}
		if stale.ServerGeneration != 2 {
			t.Fatalf("generation %d: expected server generation 2, got %d", gen, stale.ServerGeneration)
		}
	}

	snap := m.CurrentRules()
	if snap.Generation != 2 {
		t.Fatalf("committed generation changed after rejected transactions: %d", snap.Generation)
	}

	// A strictly newer generation is still accepted, proving normal updates
	// keep flowing after a rejected transaction.
	newer := ruleSync("session-1", 3)
	newer.Version = "v2"
	if _, err := m.UpdateRules("conn-1", newer); err != nil {
		t.Fatalf("newer generation rejected: %v", err)
	}
	if m.CurrentRules().Version != "v2" {
		t.Fatalf("newer transaction did not commit")
	}
}

// A rule sync arriving on a connection that is no longer registered must be
// rejected; the old connection can never write into a new session.
func TestUpdateRules_RejectsUnknownConnection(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)
	m.RegisterClient("conn-1", hello("client-a", "session-1"))
	if _, err := m.UpdateRules("conn-1", ruleSync("session-1", 1)); err != nil {
		t.Fatalf("initial commit failed: %v", err)
	}

	// Simulate the websocket dropping: hub emits a disconnect.
	m.UnregisterClient("conn-1")

	if _, err := m.UpdateRules("conn-1", ruleSync("session-1", 2)); err == nil {
		t.Fatal("expected stale connection transaction to be rejected")
	}
	if _, ok := m.PublicRuleSnapshot(); ok {
		t.Fatal("public rule snapshot must be invalidated after disconnect")
	}
}

// Payloads that claim a session different from the one owning the live
// connection are fenced off, even if they arrive over the new websocket.
func TestUpdateRules_RejectsForeignSession(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)
	m.RegisterClient("conn-2", hello("client-a", "session-2"))

	_, err := m.UpdateRules("conn-2", ruleSync("session-1", 1))
	var stale *StaleRuleSyncError
	if !errors.As(err, &stale) {
		t.Fatalf("expected StaleRuleSyncError for dead session, got %v", err)
	}

	// The current session's legitimate update still works.
	if _, err := m.UpdateRules("conn-2", ruleSync("session-2", 1)); err != nil {
		t.Fatalf("legitimate session update rejected: %v", err)
	}
}

// When the same client reconnects (new connection, new session) the previous
// session's public snapshot must not be restored; generation restarts and the
// first transaction of the new session commits cleanly.
func TestRegisterClient_ReconnectDoesNotRestoreOldState(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)
	m.RegisterClient("conn-1", hello("client-a", "session-1"))
	old := ruleSync("session-1", 7)
	old.Version = "old-rules"
	if _, err := m.UpdateRules("conn-1", old); err != nil {
		t.Fatalf("initial commit failed: %v", err)
	}

	// Reconnect: hub assigns a fresh connection id; client rotates session id.
	m.RegisterClient("conn-2", hello("client-a", "session-2"))

	if _, ok := m.PublicRuleSnapshot(); ok {
		t.Fatal("old session snapshot must not be visible after reconnect")
	}
	if _, ok := m.LookupClient("conn-1"); ok {
		t.Fatal("stale connection entry must be evicted on reconnect")
	}

	info, ok := m.LookupClient("conn-2")
	if !ok || info.SessionID != "session-2" || info.RuleGeneration != 0 {
		t.Fatalf("new session not reset correctly: %+v ok=%v", info, ok)
	}

	// Generation counter restarts for the new session: generation 1 commits.
	next := ruleSync("session-2", 1)
	next.Version = "new-rules"
	snap, err := m.UpdateRules("conn-2", next)
	if err != nil {
		t.Fatalf("new session first transaction rejected: %v", err)
	}
	if snap.Version != "new-rules" || snap.SessionID != "session-2" {
		t.Fatalf("new session snapshot mismatch: %+v", snap)
	}

	// A late, in-flight message from the dead connection/session cannot land.
	if _, err := m.UpdateRules("conn-1", ruleSync("session-1", 8)); err == nil {
		t.Fatal("dead connection must not be able to commit after reconnect")
	}
}

// A reconnect that reuses the same logical session id still fences the prior
// connection and starts from a clean generation boundary.
func TestRegisterClient_SameSessionReconnectFencesOldConnection(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)
	m.RegisterClient("conn-1", hello("client-a", "session-1"))
	if _, err := m.UpdateRules("conn-1", ruleSync("session-1", 5)); err != nil {
		t.Fatalf("initial commit failed: %v", err)
	}

	m.RegisterClient("conn-2", hello("client-a", "session-1"))

	if _, ok := m.PublicRuleSnapshot(); ok {
		t.Fatal("snapshot must be fenced even when session id is reused")
	}
	if _, err := m.UpdateRules("conn-1", ruleSync("session-1", 6)); err == nil {
		t.Fatal("old connection must be fenced after same-session reconnect")
	}
	if _, err := m.UpdateRules("conn-2", ruleSync("session-1", 1)); err != nil {
		t.Fatalf("new connection generation 1 should commit: %v", err)
	}
}

// Legacy clients that do not advertise a stable client/session id keep
// working: binding falls back to the connection id.
func TestLegacyClientFallback(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)
	m.RegisterClient("conn-legacy", &messages.ClientHelloPayload{Platform: "darwin"})

	payload := ruleSync("", 1)
	snap, err := m.UpdateRules("conn-legacy", payload)
	if err != nil {
		t.Fatalf("legacy commit failed: %v", err)
	}
	if snap.ClientID != "conn-legacy" {
		t.Fatalf("expected fallback client binding, got %q", snap.ClientID)
	}

	// Legacy payloads carry generation 0; the daemon assigns successive
	// server-side generations so their updates remain ordered.
	second, err := m.UpdateRules("conn-legacy", ruleSync("", 0))
	if err != nil {
		t.Fatalf("second legacy commit failed: %v", err)
	}
	if second.Generation <= snap.Generation {
		t.Fatalf("legacy generation must advance: first=%d second=%d", snap.Generation, second.Generation)
	}
}

// Only the client that owns the committed public snapshot can invalidate it.
// A second client connecting or disconnecting must never fence off the first
// client's live session state.
func TestClientIsolationAcrossConnections(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	// Client A establishes a session and commits a snapshot.
	m.RegisterClient("conn-a", hello("client-a", "session-a"))
	snapA, err := m.UpdateRules("conn-a", ruleSync("session-a", 1))
	if err != nil {
		t.Fatalf("client A commit failed: %v", err)
	}

	// Client B connects on its own connection; A's snapshot must survive.
	m.RegisterClient("conn-b", hello("client-b", "session-b"))
	public, ok := m.PublicRuleSnapshot()
	if !ok || public.ClientID != "client-a" {
		t.Fatalf("client A snapshot lost when client B connected: ok=%v snap=%+v", ok, public)
	}

	// B's valid transaction becomes the latest committed snapshot, but A's
	// connection remains registered and live.
	if _, err := m.UpdateRules("conn-b", ruleSync("session-b", 1)); err != nil {
		t.Fatalf("client B commit failed: %v", err)
	}
	if _, ok := m.LookupClient("conn-a"); !ok {
		t.Fatal("client A connection must remain registered while B is active")
	}

	// B disconnects. Since B owns the latest snapshot it is fenced off, and
	// A can still commit further transactions on its untouched session.
	m.UnregisterClient("conn-b")
	if _, ok := m.PublicRuleSnapshot(); ok {
		t.Fatal("client B snapshot must be invalidated after B disconnected")
	}
	if _, err := m.UpdateRules("conn-a", ruleSync("session-a", snapA.Generation+1)); err != nil {
		t.Fatalf("client A follow-up transaction must still commit: %v", err)
	}
}
