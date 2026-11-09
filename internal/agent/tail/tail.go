// Package tail follows log files line by line with persistent checkpoints,
// surviving agent restarts, log rotation (rename + create) and truncation
// (copytruncate). Each emitted line carries its file offset so the pipeline
// can derive a provider-side id (docs/adr/0004).
package tail

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Line is one complete line read from a file.
type Line struct {
	Path   string
	Offset int64 // byte offset of the line start
	Text   []byte
}

// Checkpoints persists per-file read positions.
type Checkpoints struct {
	mu   sync.Mutex
	path string
	pos  map[string]checkpoint
}

type checkpoint struct {
	Offset int64 `json:"offset"`
	// Identity of the file the offset belongs to: size at last read and the
	// first bytes, used to detect rotation and truncation.
	Size int64  `json:"size"`
	Head string `json:"head"`
}

// LoadCheckpoints reads (or initializes) the checkpoint file.
func LoadCheckpoints(path string) (*Checkpoints, error) {
	c := &Checkpoints{path: path, pos: map[string]checkpoint{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &c.pos); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Checkpoints) get(file string) (checkpoint, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp, ok := c.pos[file]
	return cp, ok
}

// Set records a position; Save persists all positions atomically.
func (c *Checkpoints) set(file string, cp checkpoint) {
	c.mu.Lock()
	c.pos[file] = cp
	c.mu.Unlock()
}

// Save writes the checkpoint file atomically.
func (c *Checkpoints) Save() error {
	c.mu.Lock()
	b, err := json.Marshal(c.pos)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Commit marks a line as delivered: the next start resumes after it.
func (c *Checkpoints) Commit(l Line, head string, size int64) {
	c.set(l.Path, checkpoint{Offset: l.Offset + int64(len(l.Text)) + 1, Size: size, Head: head})
}

// Follower tails one file.
type Follower struct {
	Path         string
	Checkpoints  *Checkpoints
	PollInterval time.Duration
	// StartAtEnd begins at the current end of a file that has no checkpoint
	// (avoids replaying years of history on first install).
	StartAtEnd bool
	// MaxLine bounds one line; longer lines are split.
	MaxLine int
}

const headLen = 64

func readHead(f *os.File) string {
	buf := make([]byte, headLen)
	n, _ := f.ReadAt(buf, 0)
	return string(buf[:n])
}

// Run emits complete lines to out until ctx ends. A partial last line is held
// until its newline arrives.
func (fl *Follower) Run(ctx context.Context, out chan<- Line) error {
	poll := fl.PollInterval
	if poll <= 0 {
		poll = 250 * time.Millisecond
	}
	maxLine := fl.MaxLine
	if maxLine <= 0 {
		maxLine = 256 << 10
	}
	// StartAtEnd only applies to a file that already existed when the
	// follower started; a file created later is read from its beginning.
	_, statErr := os.Stat(fl.Path)
	existedAtStart := statErr == nil
	var f *os.File
	var r *bufio.Reader
	var offset int64
	var head string
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	open := func() error {
		nf, err := openShared(fl.Path)
		if err != nil {
			return err
		}
		fi, err := nf.Stat()
		if err != nil {
			nf.Close()
			return err
		}
		h := readHead(nf)
		start := int64(0)
		if cp, ok := fl.Checkpoints.get(fl.Path); ok {
			// Same file (head unchanged and not shorter than the offset): resume.
			if cp.Offset <= fi.Size() && (cp.Head == h || len(cp.Head) < headLen && len(h) >= len(cp.Head) && h[:len(cp.Head)] == cp.Head) {
				start = cp.Offset
			}
		} else if fl.StartAtEnd && existedAtStart {
			start = fi.Size()
		}
		existedAtStart = false
		if _, err := nf.Seek(start, io.SeekStart); err != nil {
			nf.Close()
			return err
		}
		if f != nil {
			f.Close()
		}
		f, r, offset, head = nf, bufio.NewReaderSize(nf, 64<<10), start, h
		return nil
	}
	var partial []byte
	for {
		if f == nil {
			if err := open(); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return err
				}
				if !sleep(ctx, poll) {
					return ctx.Err()
				}
				continue
			}
		}
		chunk, err := r.ReadSlice('\n')
		if len(chunk) > 0 {
			partial = append(partial, chunk...)
		}
		if err == nil || (errors.Is(err, bufio.ErrBufferFull)) {
			if err == nil || len(partial) >= maxLine {
				text := partial
				if text[len(text)-1] == '\n' {
					text = text[:len(text)-1]
				}
				if n := len(text); n > 0 && text[n-1] == '\r' {
					text = text[:n-1]
				}
				line := Line{Path: fl.Path, Offset: offset, Text: append([]byte(nil), text...)}
				offset += int64(len(partial))
				partial = partial[:0]
				if len(head) < headLen {
					head = readHead(f)
				}
				select {
				case out <- line:
				case <-ctx.Done():
					return ctx.Err()
				}
				fl.Checkpoints.set(fl.Path, checkpoint{Offset: offset, Size: offset, Head: head})
			}
			continue
		}
		if !errors.Is(err, io.EOF) {
			return err
		}
		// At EOF: detect rotation (path now names a different file) or
		// truncation (file shorter than our offset).
		if rotated, trunc := fl.changed(f, offset+int64(len(partial)), head); rotated || trunc {
			partial = partial[:0]
			if trunc {
				fl.Checkpoints.set(fl.Path, checkpoint{})
			} else {
				fl.Checkpoints.set(fl.Path, checkpoint{Head: "\x00"}) // force start at 0 on the new file
			}
			f.Close()
			f = nil
			continue
		}
		if !sleep(ctx, poll) {
			return ctx.Err()
		}
	}
}

func (fl *Follower) changed(f *os.File, pos int64, head string) (rotated, truncated bool) {
	cur, err := os.Stat(fl.Path)
	if err != nil {
		return false, false // file removed and not yet recreated: keep reading the old one
	}
	old, err := f.Stat()
	if err != nil {
		return true, false
	}
	if !os.SameFile(cur, old) {
		return true, false
	}
	return false, cur.Size() < pos
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
