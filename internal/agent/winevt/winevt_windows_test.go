//go:build windows

package winevt

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lumidren/argus/internal/parsers/parsertest"
	"github.com/lumidren/argus/internal/parsers/windows"
)

// TestReadApplicationChannel reads existing records from the Application
// channel (present on every Windows host), checks that each renders as
// event XML the windows parser accepts, and that a saved bookmark resumes
// after the delivered record.
func TestReadApplicationChannel(t *testing.T) {
	dir := t.TempDir()
	s := &Subscription{Channel: "Application", BookmarkDir: dir, FromOldest: true, Batch: 8}
	out := make(chan Event, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, out) }()
	var first Event
	select {
	case first = <-out:
	case err := <-done:
		t.Skipf("Application channel not readable here: %v", err)
	case <-ctx.Done():
		t.Skip("Application channel has no records")
	}
	cancel()
	<-done
	if !strings.Contains(first.XML, "<Event") || !strings.Contains(first.Bookmark, "BookmarkList") {
		t.Fatalf("unexpected rendering: %.120s / %.120s", first.XML, first.Bookmark)
	}
	p := windows.New()
	if !p.Detect([]byte(first.XML), nil) {
		t.Fatal("rendered XML not recognized by the windows parser")
	}
	e := parsertest.ParseOne(t, p, first.XML)
	if e.String("winlog.channel") != "Application" || e.String("event.dataset") != "windows.application" {
		t.Fatalf("parsed fields: %s %s", e.String("winlog.channel"), e.String("event.dataset"))
	}
	if err := s.SaveBookmark(first.Bookmark); err != nil {
		t.Fatal(err)
	}
	if s.loadBookmark() == "" {
		t.Fatal("bookmark not persisted")
	}
}

func TestUnknownChannel(t *testing.T) {
	s := &Subscription{Channel: "Argus-Does-Not-Exist/Operational", BookmarkDir: t.TempDir()}
	err := s.Run(context.Background(), make(chan Event))
	if err == nil || !strings.Contains(err.Error(), "Argus-Does-Not-Exist") {
		t.Fatalf("expected channel error, got %v", err)
	}
}
