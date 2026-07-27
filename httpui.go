package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

//go:embed index.html
var uiFS embed.FS

func jsonEnvelope(kind string, data any) ([]byte, error) {
	return json.Marshal(map[string]any{"kind": kind, "data": data})
}

func (a *App) routes(mux *http.ServeMux) {
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/events", a.handleEvents)
	mux.HandleFunc("/send", a.handleSend)
	mux.HandleFunc("/typing", a.handleTyping)
	mux.HandleFunc("/nick", a.handleNick)
	mux.HandleFunc("/verify", a.handleVerify)
	mux.HandleFunc("/history", a.handleHistory)
	mux.HandleFunc("/clear-messages", a.handleClearMessages)
	mux.HandleFunc("/diag", a.handleDiag)
	mux.HandleFunc("/exit", a.handleExit)
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	a.touchActivity()
	b, err := uiFS.ReadFile("index.html")
	if err != nil {
		http.Error(w, "ui missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (a *App) identityView() IdentityView {
	return IdentityView{
		Nick:   a.currentNick(),
		FP:     a.id.FP,
		Short:  shortFP(a.id.FP),
		Safety: SafetyNumber(a.id.FP),
		IP:     primaryIP(),
		Port:   a.tcpPort,
		Disco:  a.discoPort,
		Boot:   a.boot.Format("2006-01-02 15:04:05"),
		Data:   a.dataDir,
	}
}

func (a *App) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	fl.Flush()

	ch := make(chan []byte, 512)
	a.submu.Lock()
	a.subs[ch] = true
	a.submu.Unlock()
	defer func() {
		a.submu.Lock()
		delete(a.subs, ch)
		a.submu.Unlock()
	}()

	send := func(kind string, data any) bool {
		b, err := jsonEnvelope(kind, data)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		fl.Flush()
		return true
	}

	if !send("identity", a.identityView()) {
		return
	}

	a.logmu.Lock()
	backlog := append([]LogLine(nil), a.ring...)
	a.logmu.Unlock()
	for _, l := range backlog {
		if !send("log", l) {
			return
		}
	}
	if !send("diag", a.diag.Snapshot()) {
		return
	}
	a.pushPeers()

	keep := time.NewTicker(20 * time.Second)
	defer keep.Stop()
	for {
		select {
		case b := <-ch:
			if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
				return
			}
			fl.Flush()
		case <-keep.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func decodeBody(r *http.Request, dst any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 128<<10)).Decode(dst)
}

func (a *App) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Conv string `json:"conv"`
		Body string `json:"body"`
	}
	if err := decodeBody(r, &in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if in.Conv == "" {
		in.Conv = "room"
	}
	a.touchActivity()
	a.Send(in.Conv, in.Body)
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleTyping(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Conv string `json:"conv"`
	}
	if err := decodeBody(r, &in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if in.Conv == "" {
		in.Conv = "room"
	}
	a.touchActivity()
	a.SendTyping(in.Conv)
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleNick(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Nick string `json:"nick"`
	}
	if err := decodeBody(r, &in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	n := sanitizeNick(in.Nick)
	if n == "" {
		http.Error(w, "empty nick", http.StatusBadRequest)
		return
	}
	a.touchActivity()
	a.mu.Lock()
	old := a.nick
	a.nick = n
	a.mu.Unlock()
	a.logf("SYS", "local", "display name changed %q -> %q — fingerprint %s is unchanged, so peers see a rename, not a new identity",
		old, n, shortFP(a.id.FP))
	a.sendAnnounce()
	a.emit("identity", a.identityView())
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		FP       string `json:"fp"`
		Verified bool   `json:"verified"`
	}
	if err := decodeBody(r, &in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !a.trust.SetVerified(in.FP, in.Verified) {
		http.Error(w, "unknown fingerprint", http.StatusNotFound)
		return
	}
	a.touchActivity()
	state := "unverified"
	if in.Verified {
		state = "verified"
	}
	a.logf("CRY", "local", "fingerprint %s marked %s by the operator", shortFP(in.FP), state)
	a.pushPeers()
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleHistory(w http.ResponseWriter, r *http.Request) {
	a.touchActivity()
	conv := r.URL.Query().Get("conv")
	if conv == "" {
		conv = "room"
	}
	limit := 200
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	entries := a.hist.Load(conv, limit)
	out := make([]ChatMsg, 0, len(entries))
	for _, e := range entries {
		out = append(out, ChatMsg{
			TS:   time.UnixMilli(e.TS).Format("15:04:05.000"),
			Conv: e.Conv, MID: e.MID, FP: e.FP, Nick: e.Nick,
			Self: e.Self, Body: e.Body, Enc: "stored",
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"conv": conv, "messages": out})
}

func validConversationID(conv string) bool {
	if conv == "room" {
		return true
	}
	if len(conv) < 8 || len(conv) > 128 {
		return false
	}
	for _, r := range conv {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func (a *App) handleClearMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Conv string `json:"conv"`
	}
	if err := decodeBody(r, &in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if in.Conv == "" {
		in.Conv = "room"
	}
	if !validConversationID(in.Conv) {
		http.Error(w, "invalid conversation", http.StatusBadRequest)
		return
	}

	a.touchActivity()
	a.hist.Delete(in.Conv)
	a.emit("chat-cleared", map[string]string{"conv": in.Conv})
	a.logf("SYS", "local", "cleared messages for %s — transcript erased from this local session", safeName(in.Conv))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "conv": in.Conv})
}

func (a *App) handleDiag(w http.ResponseWriter, r *http.Request) {
	a.touchActivity()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.diag.Snapshot())
}

func (a *App) handleExit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	a.requestShutdown("user requested exit")
}
