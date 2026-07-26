package main

import (
	"net/http"
	"net/http/httptest"
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
