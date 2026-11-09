// Package wal is the agent's disk-backed buffer. Records are appended to
// numbered segment files and survive restarts; a reader consumes from the
// acknowledged position, and fully acknowledged segments are deleted. This
// gives the agent at-least-once delivery through collector outages
// (docs/adr/0004).
//
// On-disk record format: 4-byte big-endian length, 4-byte CRC32 (IEEE) of
// the payload, payload. A torn tail (crash mid-write) is detected by length
// or CRC and truncated on open.
package wal

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ErrFull is returned by Append when the buffer reached MaxBytes.
var ErrFull = errors.New("wal: buffer full")

// ErrClosed is returned after Close.
var ErrClosed = errors.New("wal: closed")

const headerSize = 8

// MaxRecord bounds one record.
const MaxRecord = 4 << 20

// Options configures a WAL.
type Options struct {
	// SegmentBytes rotates to a new segment after this many bytes.
	SegmentBytes int64
	// MaxBytes bounds total unacknowledged data on disk; 0 means 1 GiB.
	MaxBytes int64
	// SyncEvery fsyncs after this many appends; 1 syncs every record.
	SyncEvery int
}

// Position identifies a record: segment number and byte offset.
type Position struct {
	Segment uint64
	Offset  int64
}

// Record is one buffered payload and the position after it.
type Record struct {
	Data []byte
	Next Position
}

// WAL is safe for one writer and one reader running concurrently.
type WAL struct {
	dir  string
	opts Options

	mu       sync.Mutex
	cond     *sync.Cond
	closed   bool
	segs     []uint64 // ascending segment numbers present on disk
	w        *os.File
	wbuf     *bufio.Writer
	wseg     uint64
	wsize    int64
	unsynced int
	total    int64 // bytes on disk across segments
	acked    Position
	read     Position
}

// Open opens or creates a WAL in dir.
func Open(dir string, opts Options) (*WAL, error) {
	if opts.SegmentBytes <= 0 {
		opts.SegmentBytes = 64 << 20
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 1 << 30
	}
	if opts.SyncEvery <= 0 {
		opts.SyncEvery = 64
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &WAL{dir: dir, opts: opts}
	w.cond = sync.NewCond(&w.mu)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".seg") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(name, ".seg"), 10, 64)
		if err != nil {
			continue
		}
		w.segs = append(w.segs, n)
	}
	sort.Slice(w.segs, func(i, j int) bool { return w.segs[i] < w.segs[j] })
	if pos, err := w.loadAck(); err == nil {
		w.acked = pos
	}
	if len(w.segs) == 0 {
		w.segs = []uint64{1}
	}
	if w.acked.Segment < w.segs[0] {
		w.acked = Position{Segment: w.segs[0]}
	}
	for _, s := range w.segs {
		fi, err := os.Stat(w.segPath(s))
		if err == nil {
			w.total += fi.Size()
		}
	}
	last := w.segs[len(w.segs)-1]
	if err := w.repairTail(last); err != nil {
		return nil, err
	}
	if err := w.openWriter(last); err != nil {
		return nil, err
	}
	w.read = w.acked
	return w, nil
}

func (w *WAL) segPath(n uint64) string {
	return filepath.Join(w.dir, fmt.Sprintf("%020d.seg", n))
}

func (w *WAL) ackPath() string { return filepath.Join(w.dir, "ack") }

func (w *WAL) loadAck() (Position, error) {
	b, err := os.ReadFile(w.ackPath())
	if err != nil {
		return Position{}, err
	}
	seg, off, ok := strings.Cut(strings.TrimSpace(string(b)), ":")
	if !ok {
		return Position{}, errors.New("wal: bad ack file")
	}
	s, err1 := strconv.ParseUint(seg, 10, 64)
	o, err2 := strconv.ParseInt(off, 10, 64)
	if err1 != nil || err2 != nil {
		return Position{}, errors.New("wal: bad ack file")
	}
	return Position{Segment: s, Offset: o}, nil
}

// repairTail truncates a torn final record left by a crash.
func (w *WAL) repairTail(seg uint64) error {
	f, err := os.OpenFile(w.segPath(seg), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var good int64
	for {
		n, err := readRecord(r, nil)
		if err != nil {
			break
		}
		good += int64(n)
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() != good {
		w.total -= fi.Size() - good
		return f.Truncate(good)
	}
	return nil
}

func (w *WAL) openWriter(seg uint64) error {
	f, err := os.OpenFile(w.segPath(seg), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.w, w.wseg, w.wsize = f, seg, fi.Size()
	w.wbuf = bufio.NewWriterSize(f, 64<<10)
	return nil
}

// readRecord reads one record; it returns the bytes consumed. When out is
// non-nil the payload is appended to it.
func readRecord(r *bufio.Reader, out *[]byte) (int, error) {
	var hdr [headerSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	sum := binary.BigEndian.Uint32(hdr[4:])
	if n > MaxRecord {
		return 0, errors.New("wal: corrupt record length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	if crc32.ChecksumIEEE(buf) != sum {
		return 0, errors.New("wal: checksum mismatch")
	}
	if out != nil {
		*out = buf
	}
	return headerSize + int(n), nil
}

// Append buffers one record. It returns ErrFull when the disk budget is
// exhausted; the caller applies back-pressure to its input.
func (w *WAL) Append(data []byte) error {
	if len(data) > MaxRecord {
		return fmt.Errorf("wal: record of %d bytes exceeds %d", len(data), MaxRecord)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	size := int64(headerSize + len(data))
	if w.total+size > w.opts.MaxBytes {
		return ErrFull
	}
	if w.wsize > 0 && w.wsize+size > w.opts.SegmentBytes {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	var hdr [headerSize]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(data)))
	binary.BigEndian.PutUint32(hdr[4:], crc32.ChecksumIEEE(data))
	if _, err := w.wbuf.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.wbuf.Write(data); err != nil {
		return err
	}
	w.wsize += size
	w.total += size
	w.unsynced++
	if w.unsynced >= w.opts.SyncEvery {
		if err := w.syncLocked(); err != nil {
			return err
		}
	} else if err := w.wbuf.Flush(); err != nil {
		return err
	}
	w.cond.Broadcast()
	return nil
}

func (w *WAL) syncLocked() error {
	if err := w.wbuf.Flush(); err != nil {
		return err
	}
	w.unsynced = 0
	return w.w.Sync()
}

// Sync flushes and fsyncs pending appends.
func (w *WAL) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	return w.syncLocked()
}

func (w *WAL) rotate() error {
	if err := w.syncLocked(); err != nil {
		return err
	}
	if err := w.w.Close(); err != nil {
		return err
	}
	next := w.wseg + 1
	w.segs = append(w.segs, next)
	return w.openWriter(next)
}

// ReadBatch returns up to max records after the read position, waiting until
// at least one is available or stop is closed. Records are not acknowledged
// until Ack is called with a Next position.
func (w *WAL) ReadBatch(max int, stop <-chan struct{}) ([]Record, error) {
	w.mu.Lock()
	for {
		if w.closed {
			w.mu.Unlock()
			return nil, ErrClosed
		}
		if w.read.Segment < w.wseg || w.read.Offset < w.wsize {
			break
		}
		select {
		case <-stop:
			w.mu.Unlock()
			return nil, nil
		default:
		}
		waitWithStop(w.cond, stop)
	}
	pos := w.read
	writeSeg, writeSize := w.wseg, w.wsize
	w.mu.Unlock()
	var out []Record
	for len(out) < max {
		if pos.Segment > writeSeg || (pos.Segment == writeSeg && pos.Offset >= writeSize) {
			break
		}
		f, err := os.Open(w.segPath(pos.Segment))
		if err != nil {
			return out, err
		}
		if _, err := f.Seek(pos.Offset, io.SeekStart); err != nil {
			f.Close()
			return out, err
		}
		r := bufio.NewReader(f)
		limit := int64(-1)
		if pos.Segment == writeSeg {
			limit = writeSize
		}
		for len(out) < max && (limit < 0 || pos.Offset < limit) {
			var data []byte
			n, err := readRecord(r, &data)
			if err != nil {
				break
			}
			pos.Offset += int64(n)
			out = append(out, Record{Data: data, Next: pos})
		}
		f.Close()
		if len(out) < max && pos.Segment < writeSeg {
			pos = Position{Segment: pos.Segment + 1}
			continue
		}
		break
	}
	w.mu.Lock()
	w.read = pos
	w.mu.Unlock()
	return out, nil
}

// waitWithStop waits on cond until signalled or stop is closed.
func waitWithStop(c *sync.Cond, stop <-chan struct{}) {
	done := make(chan struct{})
	go func() {
		select {
		case <-stop:
			c.L.Lock()
			c.Broadcast()
			c.L.Unlock()
		case <-done:
		}
	}()
	c.Wait()
	close(done)
}

// Rewind moves the read position back to the acknowledged position so
// unacknowledged records are delivered again (after a send failure).
func (w *WAL) Rewind() {
	w.mu.Lock()
	w.read = w.acked
	w.mu.Unlock()
}

// Ack records that every record up to pos was delivered, persists the
// position, and deletes fully acknowledged segments.
func (w *WAL) Ack(pos Position) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	if pos.Segment < w.acked.Segment || (pos.Segment == w.acked.Segment && pos.Offset <= w.acked.Offset) {
		return nil
	}
	tmp := w.ackPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d:%d", pos.Segment, pos.Offset)), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, w.ackPath()); err != nil {
		return err
	}
	w.acked = pos
	keep := w.segs[:0]
	for _, s := range w.segs {
		if s < pos.Segment && s != w.wseg {
			if fi, err := os.Stat(w.segPath(s)); err == nil {
				w.total -= fi.Size()
			}
			_ = os.Remove(w.segPath(s))
			continue
		}
		keep = append(keep, s)
	}
	w.segs = keep
	return nil
}

// Pending returns unacknowledged bytes on disk.
func (w *WAL) Pending() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var n int64
	for _, s := range w.segs {
		size := int64(0)
		if s == w.wseg {
			size = w.wsize
		} else if fi, err := os.Stat(w.segPath(s)); err == nil {
			size = fi.Size()
		}
		switch {
		case s < w.acked.Segment:
		case s == w.acked.Segment:
			n += size - w.acked.Offset
		default:
			n += size
		}
	}
	return n
}

// Close syncs and closes the writer.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	w.cond.Broadcast()
	err := w.syncLocked()
	if cerr := w.w.Close(); err == nil {
		err = cerr
	}
	return err
}
