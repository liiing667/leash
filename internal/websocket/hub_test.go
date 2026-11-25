package websocket

// These tests were added after a production panic where slow or stalled websocket clients
// caused the hub to attempt a non-blocking send on a channel that had just been closed
// during client teardown. This reproduces the race condition to ensure enqueue doesn't
// panic and verifies the revised drop-oldest ring-buffer behavior which provides the
// resilience fix.

import (
	"testing"
	"time"
)

func TestHubEnqueueAfterClientClosureDoesNotPanic(t *testing.T) {
	t.Parallel()

	hub := NewWebSocketHub(nil, 1, 0, 0)
	client := &client{
		id:     "test-client",
		send:   make(chan []byte, 1),
		closed: make(chan struct{}),
		hub:    hub,
	}

	// Simulate the client being torn down before the hub finishes broadcasting.
	close(client.closed)
	close(client.send)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("enqueue panicked: %v", r)
		}
	}()

	hub.enqueue(client, []byte("payload"))
}

func TestHubEnqueueDropsOldestMessageWhenFull(t *testing.T) {
	t.Parallel()

	hub := NewWebSocketHub(nil, 1, 0, 0)
	client := &client{
		id:     "ring-client",
		send:   make(chan []byte, 2),
		closed: make(chan struct{}),
		hub:    hub,
	}

	client.closeMu.Lock()
	client.send <- []byte("older")
	client.send <- []byte("newer")
	client.closeMu.Unlock()

	hub.enqueue(client, []byte("latest"))

	first := <-client.send
	if string(first) != "newer" {
		t.Fatalf("expected 'newer' to remain, got %q", string(first))
	}

	second := <-client.send
	if string(second) != "latest" {
		t.Fatalf("expected 'latest' to be enqueued, got %q", string(second))
	}
}

// When a websocket client is unregistered the hub must emit its
// connection-scoped id on Disconnects so consumers can fence off state
// belonging to the dead connection before a reconnect establishes a new one.
func TestHubEmitsDisconnectNotification(t *testing.T) {
	t.Parallel()

	hub := NewWebSocketHub(nil, 1, 0, 0)
	go hub.Run()
	t.Cleanup(func() { /* hub has no shutdown; test exits and goroutine ends */ })

	c := &client{
		id:     "disconnect-client",
		send:   make(chan []byte, 8),
		closed: make(chan struct{}),
		hub:    hub,
	}

	hub.register <- c

	deadline := time.After(2 * time.Second)
	for hub.getClient(c.id) == nil {
		select {
		case <-deadline:
			t.Fatal("client was never registered")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	hub.unregister <- c

	select {
	case id := <-hub.Disconnects():
		if id != c.id {
			t.Fatalf("expected disconnect for %q, got %q", c.id, id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive disconnect notification")
	}

	if hub.getClient(c.id) != nil {
		t.Fatal("client still present after unregister")
	}
}
