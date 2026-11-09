package tail

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func collect(t *testing.T, ch <-chan Line, n int) []Line {
	t.Helper()
	var out []Line
	deadline := time.After(5 * time.Second)
	for len(out) < n {
		select {
		case l := <-ch:
			out = append(out, l)
		case <-deadline:
			t.Fatalf("got %d of %d lines", len(out), n)
		}
	}
	return out
}

func start(t *testing.T, path, cpPath string, atEnd bool) (chan Line, *Checkpoints, context.CancelFunc, chan error) {
	t.Helper()
	cp, err := LoadCheckpoints(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan Line, 100)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	fl := &Follower{Path: path, Checkpoints: cp, PollInterval: 10 * time.Millisecond, StartAtEnd: atEnd}
	go func() { done <- fl.Run(ctx, ch) }()
	return ch, cp, cancel, done
}

func TestFollowPartialLinesAndOffsets(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	appendFile(t, p, "first\r\nsecond\npart")
	ch, _, cancel, done := start(t, p, filepath.Join(dir, "cp.json"), false)
	defer func() { cancel(); <-done }()
	lines := collect(t, ch, 2)
	if string(lines[0].Text) != "first" || string(lines[1].Text) != "second" || lines[1].Offset != 7 {
		t.Fatalf("lines %+v", lines)
	}
	select {
	case l := <-ch:
		t.Fatalf("partial line emitted early: %q", l.Text)
	case <-time.After(50 * time.Millisecond):
	}
	appendFile(t, p, "ial\n")
	if l := collect(t, ch, 1); string(l[0].Text) != "partial" {
		t.Fatalf("joined partial: %q", l[0].Text)
	}
}

func TestResumeFromCheckpoint(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	cpPath := filepath.Join(dir, "cp.json")
	appendFile(t, p, "a\nb\nc\n")
	ch, cp, cancel, done := start(t, p, cpPath, false)
	collect(t, ch, 3)
	cancel()
	<-done
	if err := cp.Save(); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "d\n")
	ch, _, cancel, done = start(t, p, cpPath, false)
	defer func() { cancel(); <-done }()
	if l := collect(t, ch, 1); string(l[0].Text) != "d" {
		t.Fatalf("resume replayed history: %q", l[0].Text)
	}
}

func TestRotationAndTruncation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	appendFile(t, p, "old-1\nold-2\n")
	ch, _, cancel, done := start(t, p, filepath.Join(dir, "cp.json"), false)
	defer func() { cancel(); <-done }()
	collect(t, ch, 2)
	// rename + create (logrotate default)
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "new-1\n")
	if l := collect(t, ch, 1); string(l[0].Text) != "new-1" {
		t.Fatalf("after rotation: %q", l[0].Text)
	}
	// copytruncate: file shrinks to zero, then grows again
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	appendFile(t, p, "after-truncate\n")
	if l := collect(t, ch, 1); string(l[0].Text) != "after-truncate" {
		t.Fatalf("after truncation: %q", l[0].Text)
	}
}

func TestStartAtEndAndMissingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "later.log")
	ch, _, cancel, done := start(t, p, filepath.Join(dir, "cp.json"), true)
	defer func() { cancel(); <-done }()
	time.Sleep(30 * time.Millisecond)
	appendFile(t, p, "hello\n") // file created after the follower started
	if l := collect(t, ch, 1); string(l[0].Text) != "hello" {
		t.Fatalf("got %q", l[0].Text)
	}
}
