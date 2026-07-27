package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHistoryIsMemoryOnlyAndDeleteClearsConversation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	history := OpenHistory(dir)
	history.Append(HistEntry{Conv: "room", Body: "ephemeral", MID: "one"})

	if messages := history.Load("room", 200); len(messages) != 1 {
		t.Fatalf("history length = %d, want 1", len(messages))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("history directory contains %d entries, want 0", len(entries))
	}

	history.Delete("room")
	if messages := history.Load("room", 200); len(messages) != 0 {
		t.Fatalf("history length after delete = %d, want 0", len(messages))
	}
}

func TestOpenHistoryRemovesLegacyTranscriptFiles(t *testing.T) {
	dataDir := t.TempDir()
	dir := filepath.Join(dataDir, "history")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dataDir, "identity.json")
	trust := filepath.Join(dataDir, "known_peers.json")
	keep := filepath.Join(dir, "keep.txt")
	for path, content := range map[string]string{
		identity: "identity-config",
		trust:    "trust-config",
		keep:     "unrelated-history-note",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	legacy := filepath.Join(dir, "room.jsonl")
	if err := os.WriteFile(legacy, []byte(`{"body":"old"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_ = OpenHistory(dir)

	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy transcript still exists, stat err = %v", err)
	}
	for path, want := range map[string]string{
		identity: "identity-config",
		trust:    "trust-config",
		keep:     "unrelated-history-note",
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("preserved file %s was removed: %v", path, err)
		}
		if string(got) != want {
			t.Fatalf("preserved file %s changed: %q != %q", path, got, want)
		}
	}
}

func TestRestartRetainsIdentityAndTrustButStartsWithEmptyTranscript(t *testing.T) {
	dataDir := t.TempDir()
	identityPath := filepath.Join(dataDir, "identity.json")
	trustPath := filepath.Join(dataDir, "known_peers.json")
	historyDir := filepath.Join(dataDir, "history")

	firstIdentity, created, err := LoadOrCreateIdentity(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first identity load did not create an identity")
	}
	const peerFP = "0123456789abcdef0123456789abcdef"
	firstTrust := LoadTrustStore(trustPath)
	firstTrust.Observe(peerFP, "trusted-demo-peer")
	if !firstTrust.SetVerified(peerFP, true) {
		t.Fatal("could not verify test peer")
	}

	firstHistory := OpenHistory(historyDir)
	firstHistory.Append(HistEntry{Conv: "room", Body: "must not survive restart", MID: "one"})
	if messages := firstHistory.Load("room", 200); len(messages) != 1 {
		t.Fatalf("current-session history length = %d, want 1", len(messages))
	}

	restartedIdentity, created, err := LoadOrCreateIdentity(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("restart unexpectedly replaced the existing identity")
	}
	if restartedIdentity.FP != firstIdentity.FP {
		t.Fatalf("identity fingerprint changed across restart: %s != %s", restartedIdentity.FP, firstIdentity.FP)
	}
	restartedTrust := LoadTrustStore(trustPath)
	if restartedTrust.Count() != 1 || !restartedTrust.IsVerified(peerFP) {
		t.Fatal("trusted-peer store did not survive restart")
	}
	restartedHistory := OpenHistory(historyDir)
	if messages := restartedHistory.Load("room", 200); len(messages) != 0 {
		t.Fatalf("restart restored %d messages, want 0", len(messages))
	}
}
