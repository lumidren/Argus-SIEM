package wal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readAll(t *testing.T, w *WAL, n int) []Record {
	t.Helper()
	var out []Record
	stop := make(chan struct{})
	timer := time.AfterFunc(5*time.Second, func() { close(stop) })
	defer timer.Stop()
	for len(out) < n {
		recs, err := w.ReadBatch(n-len(out), stop)
		if err != nil {
			t.Fatal(err)
		}
		if recs == nil {
			t.Fatalf("timed out after %d of %d records", len(out), n)
		}
		out = append(out, recs...)
	}
	return out
}

func TestAppendReadAckAcrossSegments(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, Options{SegmentBytes: 256, SyncEvery: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if err := w.Append([]byte(fmt.Sprintf("record-%03d", i))); err != nil {
			t.Fatal(err)
		}
	}
	segs, _ := filepath.Glob(filepath.Join(dir, "*.seg"))
	if len(segs) < 3 {
		t.Fatalf("expected rotation, got %d segments", len(segs))
	}
	recs := readAll(t, w, 50)
	for i, r := range recs {
		if string(r.Data) != fmt.Sprintf("record-%03d", i) {
			t.Fatalf("order broken at %d: %s", i, r.Data)
		}
	}
	if err := w.Ack(recs[49].Next); err != nil {
		t.Fatal(err)
	}
	segs, _ = filepath.Glob(filepath.Join(dir, "*.seg"))
	if len(segs) != 1 {
		t.Fatalf("acked segments must be deleted, %d left", len(segs))
	}
	if w.Pending() != 0 {
		t.Fatalf("pending %d", w.Pending())
	}
	_ = w.Close()
}

func TestRestartResumesFromAck(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, Options{SegmentBytes: 128, SyncEvery: 1})
	for i := 0; i < 20; i++ {
		_ = w.Append([]byte(fmt.Sprintf("r%02d", i)))
	}
	recs := readAll(t, w, 20)
	_ = w.Ack(recs[9].Next) // delivered the first 10
	_ = w.Close()

	w, err := Open(dir, Options{SegmentBytes: 128, SyncEvery: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	recs = readAll(t, w, 10)
	if string(recs[0].Data) != "r10" || string(recs[9].Data) != "r19" {
		t.Fatalf("resume: first=%s last=%s", recs[0].Data, recs[9].Data)
	}
}

func TestRewindRedelivers(t *testing.T) {
	w, _ := Open(t.TempDir(), Options{})
	defer w.Close()
	for i := 0; i < 5; i++ {
		_ = w.Append([]byte{byte('a' + i)})
	}
	first := readAll(t, w, 5)
	w.Rewind() // send failed: nothing was acked
	again := readAll(t, w, 5)
	if string(first[0].Data) != string(again[0].Data) || len(again) != 5 {
		t.Fatal("rewind must redeliver unacked records")
	}
}

func TestTornTailIsTruncated(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, Options{SyncEvery: 1})
	_ = w.Append([]byte("good-1"))
	_ = w.Append([]byte("good-2"))
	_ = w.Close()
	segs, _ := filepath.Glob(filepath.Join(dir, "*.seg"))
	f, _ := os.OpenFile(segs[0], os.O_WRONLY|os.O_APPEND, 0o600)
	_, _ = f.Write([]byte{0, 0, 0, 50, 1, 2, 3, 4, 'x', 'y'}) // header promising 50 bytes, then crash
	f.Close()
	w, err := Open(dir, Options{SyncEvery: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	_ = w.Append([]byte("good-3"))
	recs := readAll(t, w, 3)
	if string(recs[2].Data) != "good-3" {
		t.Fatalf("torn tail not repaired: %q", recs[2].Data)
	}
}

func TestFullAndLimits(t *testing.T) {
	w, _ := Open(t.TempDir(), Options{MaxBytes: 64})
	defer w.Close()
	var err error
	for i := 0; i < 10 && err == nil; i++ {
		err = w.Append([]byte("0123456789"))
	}
	if !errors.Is(err, ErrFull) {
		t.Fatalf("expected ErrFull, got %v", err)
	}
	if err := w.Append(make([]byte, MaxRecord+1)); err == nil {
		t.Fatal("oversize record accepted")
	}
}

func TestReadBatchStops(t *testing.T) {
	w, _ := Open(t.TempDir(), Options{})
	stop := make(chan struct{})
	go func() { time.Sleep(50 * time.Millisecond); close(stop) }()
	recs, err := w.ReadBatch(10, stop)
	if err != nil || recs != nil {
		t.Fatalf("stop should return nil: %v %v", recs, err)
	}
	_ = w.Close()
	if _, err := w.ReadBatch(1, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
}
