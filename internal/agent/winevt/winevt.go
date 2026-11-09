// Package winevt reads Windows Event Log channels through wevtapi pull
// subscriptions and renders each record as event XML (the format the
// windows parser expects). A bookmark per channel is persisted so restarts
// resume after the last delivered record.
package winevt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Event is one rendered record.
type Event struct {
	Channel string
	XML     string
	// Bookmark is the bookmark XML after this record; persist it once the
	// record is safely buffered.
	Bookmark string
}

// ErrUnsupported is returned on non-Windows platforms.
var ErrUnsupported = errors.New("winevt: Windows Event Log is only available on Windows")

// Subscription follows one channel.
type Subscription struct {
	Channel string
	// Query is an XPath filter; empty means "*".
	Query string
	// BookmarkDir stores <channel>.bookmark files.
	BookmarkDir string
	// FromOldest reads existing records when no bookmark exists; otherwise
	// only future records are delivered.
	FromOldest bool
	// Batch is the number of records fetched per EvtNext call.
	Batch int
}

// BookmarkPath returns the file used to persist the channel bookmark.
func (s *Subscription) BookmarkPath() string {
	name := strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(s.Channel)
	return filepath.Join(s.BookmarkDir, name+".bookmark")
}

// SaveBookmark persists a bookmark atomically.
func (s *Subscription) SaveBookmark(xml string) error {
	if xml == "" {
		return nil
	}
	if err := os.MkdirAll(s.BookmarkDir, 0o700); err != nil {
		return err
	}
	p := s.BookmarkPath()
	if err := os.WriteFile(p+".tmp", []byte(xml), 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

func (s *Subscription) loadBookmark() string {
	b, err := os.ReadFile(s.BookmarkPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Run delivers events to out until ctx ends.
func (s *Subscription) Run(ctx context.Context, out chan<- Event) error {
	return s.run(ctx, out)
}
