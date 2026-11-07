package watcher

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	w := &Watcher{files: map[string]struct{}{filepath.Clean(path): {}}}

	if !w.watched(path) {
		t.Fatal("watched path must match")
	}
	if w.watched(path + ".other") {
		t.Fatal("unrelated path must not match")
	}
}

func TestNewRejectsMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "rules.txt")
	if _, err := New([]string{path}, func() error { return nil }, discardLogger()); err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestRunReloadsAndStops(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(path, []byte("one.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	w, err := New([]string{path}, func() error {
		calls.Add(1)
		return nil
	}, discardLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	if err := os.WriteFile(path, []byte("two.test\n"), 0o600); err != nil {
		cancel()
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == 0 {
		cancel()
		t.Fatal("reload was not triggered")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not stop")
	}
}

func TestRunStopsOnContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte("one.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w, err := New([]string{path}, func() error { return nil }, discardLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not stop")
	}
}

func TestRunLogsReloadResult(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	w := &Watcher{
		reload: func() error { return errors.New("broken rules") },
		log:    logger,
	}
	w.run()
	if !strings.Contains(logs.String(), "rules reload failed") {
		t.Fatalf("logs = %q", logs.String())
	}

	logs.Reset()
	w.reload = func() error { return nil }
	w.run()
	if !strings.Contains(logs.String(), "rules reloaded") {
		t.Fatalf("logs = %q", logs.String())
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
