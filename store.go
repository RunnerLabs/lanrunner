package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// HistEntry is retained only in process memory. Chat transcripts are deliberately
// ephemeral: they are never written to the Lan Runner data directory.
type HistEntry struct {
	Kind      string `json:"k,omitempty"` // "" = message, "ack" = delivery receipt
	TS        int64  `json:"ts"`
	Conv      string `json:"conv"`
	FP        string `json:"fp,omitempty"`
	Nick      string `json:"nick,omitempty"`
	Self      bool   `json:"self,omitempty"`
	Body      string `json:"body,omitempty"`
	MID       string `json:"mid,omitempty"`
	Delivered int    `json:"-"`
}

type History struct {
	dir     string
	mu      sync.Mutex
	entries map[string][]HistEntry
}

func OpenHistory(dir string) *History {
	_ = os.MkdirAll(dir, 0o700)
	h := &History{dir: dir, entries: map[string][]HistEntry{}}
	h.removeLegacyFiles()
	return h
}

// safeName keeps conversation ids stable and prevents path traversal while
// removing transcript files created by releases before ephemeral history.
func safeName(conv string) string {
	if conv == "room" {
		return "room"
	}
	var sb strings.Builder
	for _, r := range conv {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			sb.WriteRune(r)
		}
	}
	s := sb.String()
	if s == "" {
		return "unknown"
	}
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

func (h *History) removeLegacyFiles() {
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		_ = os.Remove(filepath.Join(h.dir, entry.Name()))
	}
}

func (h *History) Append(e HistEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	name := safeName(e.Conv)
	h.entries[name] = append(h.entries[name], e)
}

func (h *History) MarkDelivered(conv, mid string) {
	if mid == "" {
		return
	}
	h.Append(HistEntry{Kind: "ack", Conv: conv, MID: mid, TS: nowMS()})
}

// Load returns the last limit messages from this process only, with delivery
// receipts folded in. Relaunching Lan Runner starts with an empty transcript.
func (h *History) Load(conv string, limit int) []HistEntry {
	h.mu.Lock()
	defer h.mu.Unlock()

	stored := h.entries[safeName(conv)]
	msgs := make([]HistEntry, 0, len(stored))
	acks := map[string]int{}
	for _, entry := range stored {
		if entry.Kind == "ack" {
			acks[entry.MID]++
			continue
		}
		msgs = append(msgs, entry)
	}

	if limit > 0 && len(msgs) > limit {
		msgs = msgs[len(msgs)-limit:]
	}
	out := append([]HistEntry(nil), msgs...)
	for i := range out {
		out[i].Delivered = acks[out[i].MID]
	}
	return out
}

// Delete permanently removes one conversation from the current local session.
func (h *History) Delete(conv string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.entries, safeName(conv))
}

// Conversations lists conversations held in memory during this process.
func (h *History) Conversations() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.entries))
	for conv := range h.entries {
		out = append(out, conv)
	}
	return out
}

// Close erases every in-memory transcript and removes any legacy disk history.
func (h *History) Close() {
	h.mu.Lock()
	h.entries = map[string][]HistEntry{}
	h.mu.Unlock()
	h.removeLegacyFiles()
}
