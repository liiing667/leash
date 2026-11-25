package suggest

import (
	"testing"
	"time"

	"github.com/strongdm/leash/internal/policy/suggest/pattern"
	"github.com/strongdm/leash/internal/websocket"
)

func TestBuildSequencesFromLogsGroupsByPrincipal(t *testing.T) {
	logs := []websocket.LogEntry{
		{Time: "2025-10-11T15:04:05Z", Event: "file.open", Path: "/etc/ssh/sshd_config", Exe: "vim", Decision: "permit"},
		{Time: "2025-10-11T15:04:08Z", Event: "file.open", Path: "/etc/ssh/ssh_config", Exe: "vim", Decision: "permit"},
		{Time: "2025-10-11T15:06:05Z", Event: "http.request", Addr: "api.example.com", Tool: "curl", Decision: "permit"},
	}

	seqs := BuildSequencesFromLogs(logs, 5*time.Minute)
	if len(seqs) != 2 {
		t.Fatalf("expected 2 sequences, got %d", len(seqs))
	}

	var fileSeq, httpSeq pattern.Sequence
	for _, seq := range seqs {
		if seq.Principal == "vim" {
			fileSeq = seq
		}
		if seq.Principal == "curl" {
			httpSeq = seq
		}
	}

	if len(fileSeq.Events) != 2 {
		t.Fatalf("expected 2 file events, got %d", len(fileSeq.Events))
	}
	if fileSeq.Events[0].ResourceClass != "unix.file" {
		t.Fatalf("unexpected resource class %s", fileSeq.Events[0].ResourceClass)
	}
	if httpSeq.Events[0].ResourceClass != "http.host" {
		t.Fatalf("expected http host resource, got %s", httpSeq.Events[0].ResourceClass)
	}
}

func TestBuildSequencesFromLogsIsIndependentOfObjectOrder(t *testing.T) {
	logs := []websocket.LogEntry{
		{Time: "2025-10-11T15:04:05Z", Event: "file.open", Path: "/etc/ssh/ssh_config", Exe: "vim", Decision: "permit"},
		{Time: "2025-10-11T15:04:05Z", Event: "file.open", Path: "/etc/ssh/sshd_config", Exe: "vim", Decision: "permit"},
		{Time: "2025-10-11T15:04:05Z", Event: "http.request", Addr: "api.example.com", Tool: "curl", Decision: "permit"},
	}
	reordered := []websocket.LogEntry{logs[2], logs[0], logs[1]}

	got := BuildSequencesFromLogs(logs, 5*time.Minute)
	other := BuildSequencesFromLogs(reordered, 5*time.Minute)
	if len(got) != len(other) {
		t.Fatalf("sequence count differs: %d vs %d", len(got), len(other))
	}
	for i := range got {
		if got[i].SessionID != other[i].SessionID || got[i].Principal != other[i].Principal {
			t.Fatalf("sequence %d identity differs: %#v vs %#v", i, got[i], other[i])
		}
		if len(got[i].Events) != len(other[i].Events) {
			t.Fatalf("sequence %d event count differs", i)
		}
		for j := range got[i].Events {
			if got[i].Events[j].ResourceFacet != other[i].Events[j].ResourceFacet {
				t.Fatalf("sequence %d event %d order differs: %q vs %q",
					i, j, got[i].Events[j].ResourceFacet, other[i].Events[j].ResourceFacet)
			}
		}
	}
}
