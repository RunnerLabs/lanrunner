package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// HistEntry is one line of an append-only conversation log. Delivery receipts
// are appended as their own records rather than rewriting history in place,
// which keeps the file append-only and crash-safe.
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
	dir   string
	mu    sync.Mutex
	files map[string]*os.File
}

func OpenHistory(dir string) *History {
	_ = os.MkdirAll(dir, 0o700)
	return &History{dir: dir, files: map[string]*os.File{}}
}

// safeName keeps conversation ids from escaping the history directory.
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

func (h *History) handle(conv string) *os.File {
	name := safeName(conv)
	if f, ok := h.files[name]; ok {
		return f
	}
	f, err := os.OpenFile(filepath.Join(h.dir, name+".jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil
	}
	h.files[name] = f
	return f
}

func (h *History) Append(e HistEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f := h.handle(e.Conv)
	if f == nil {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
}

func (h *History) MarkDelivered(conv, mid string) {
	if mid == "" {
		return
	}
	h.Append(HistEntry{Kind: "ack", Conv: conv, MID: mid, TS: nowMS()})
}

// Load returns the last `limit` messages of a conversation with delivery
// receipts already folded in.
func (h *History) Load(conv string, limit int) []HistEntry {
	h.mu.Lock()
	defer h.mu.Unlock()

	path := filepath.Join(h.dir, safeName(conv)+".jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var msgs []HistEntry
	acks := map[string]int{}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e HistEntry
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		if e.Kind == "ack" {
			acks[e.MID]++
			continue
		}
		msgs = append(msgs, e)
	}

	if limit > 0 && len(msgs) > limit {
		msgs = msgs[len(msgs)-limit:]
	}
	for i := range msgs {
		msgs[i].Delivered = acks[msgs[i].MID]
	}
	return msgs
}

// Conversations lists conversation ids that have stored history.
func (h *History) Conversations() []string {
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".jsonl") {
			out = append(out, strings.TrimSuffix(n, ".jsonl"))
		}
	}
	return out
}

func (h *History) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, f := range h.files {
		_ = f.Close()
	}
	h.files = map[string]*os.File{}
}
