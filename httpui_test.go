package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHandleExitRequestsShutdown(t *testing.T) {
	app := &App{
		subs:     map[chan []byte]bool{},
		shutdown: make(chan string, 1),
	}
	request := httptest.NewRequest(http.MethodPost, "/exit", nil)
	response := httptest.NewRecorder()

	app.handleExit(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("exit status = %d, want %d", response.Code, http.StatusOK)
	}
	select {
	case reason := <-app.shutdown:
		if reason != "user requested exit" {
			t.Fatalf("shutdown reason = %q", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("exit handler did not request shutdown")
	}
}

func TestHandleExitRejectsGet(t *testing.T) {
	app := &App{}
	request := httptest.NewRequest(http.MethodGet, "/exit", nil)
	response := httptest.NewRecorder()

	app.handleExit(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /exit status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleClearMessagesErasesConversation(t *testing.T) {
	history := OpenHistory(filepath.Join(t.TempDir(), "history"))
	history.Append(HistEntry{Conv: "room", Body: "private test message", MID: "one"})
	app := &App{
		hist: history,
		subs: map[chan []byte]bool{},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/clear-messages",
		bytes.NewBufferString(`{"conv":"room"}`),
	)
	response := httptest.NewRecorder()

	app.handleClearMessages(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("clear-messages status = %d, want %d", response.Code, http.StatusOK)
	}
	if messages := history.Load("room", 200); len(messages) != 0 {
		t.Fatalf("history length = %d, want 0", len(messages))
	}
	if !strings.Contains(response.Body.String(), `"ok":true`) {
		t.Fatalf("clear-messages response = %q, want ok", response.Body.String())
	}
}

func TestHandleClearMessagesRejectsInvalidConversation(t *testing.T) {
	app := &App{
		hist: OpenHistory(filepath.Join(t.TempDir(), "history")),
		subs: map[chan []byte]bool{},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/clear-messages",
		bytes.NewBufferString(`{"conv":"../../identity.json"}`),
	)
	response := httptest.NewRecorder()

	app.handleClearMessages(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid clear-messages status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestHistoryHandlerReturnsSentAndReceivedMessagesInCurrentSession(t *testing.T) {
	history := OpenHistory(filepath.Join(t.TempDir(), "history"))
	history.Append(HistEntry{Conv: "room", Body: "sent in this session", MID: "one", Self: true})
	history.Append(HistEntry{Conv: "room", Body: "received in this session", MID: "two"})
	app := &App{
		hist: history,
		subs: map[chan []byte]bool{},
	}
	request := httptest.NewRequest(http.MethodGet, "/history?conv=room&limit=200", nil)
	response := httptest.NewRecorder()

	app.handleHistory(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("history status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{"sent in this session", "received in this session"} {
		if !strings.Contains(body, want) {
			t.Fatalf("history response %q does not contain %q", body, want)
		}
	}
}
