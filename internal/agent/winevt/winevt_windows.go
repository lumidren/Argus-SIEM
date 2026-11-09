//go:build windows

package winevt

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wevtapi               = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe      = wevtapi.NewProc("EvtSubscribe")
	procEvtNext           = wevtapi.NewProc("EvtNext")
	procEvtRender         = wevtapi.NewProc("EvtRender")
	procEvtClose          = wevtapi.NewProc("EvtClose")
	procEvtCreateBookmark = wevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = wevtapi.NewProc("EvtUpdateBookmark")
)

const (
	evtSubscribeToFutureEvents      = 1
	evtSubscribeStartAtOldestRecord = 2
	evtSubscribeStartAfterBookmark  = 3
	evtRenderEventXML               = 1
	evtRenderBookmark               = 2
	errorNoMoreItems                = syscall.Errno(259)
	errorInsufficientBuffer         = syscall.Errno(122)
	errorInvalidOperation           = syscall.Errno(4317)
	errorEvtChannelNotFound         = syscall.Errno(15007)
)

type evtHandle uintptr

func evtClose(h evtHandle) {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}

func createBookmark(xml string) (evtHandle, error) {
	var p *uint16
	if xml != "" {
		var err error
		if p, err = windows.UTF16PtrFromString(xml); err != nil {
			return 0, err
		}
	}
	h, _, err := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(p)))
	if h == 0 {
		return 0, fmt.Errorf("EvtCreateBookmark: %w", err)
	}
	return evtHandle(h), nil
}

// render returns the XML rendering of an event or bookmark handle.
func render(h evtHandle, flag uint32) (string, error) {
	var used, props uint32
	buf := make([]uint16, 4096)
	for {
		r, _, err := procEvtRender.Call(0, uintptr(h), uintptr(flag), uintptr(len(buf)*2),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return windows.UTF16ToString(buf[:used/2]), nil
		}
		if errors.Is(err, errorInsufficientBuffer) && int(used/2) > len(buf) {
			buf = make([]uint16, used/2+1)
			continue
		}
		return "", fmt.Errorf("EvtRender: %w", err)
	}
}

func (s *Subscription) run(ctx context.Context, out chan<- Event) error {
	batch := s.Batch
	if batch <= 0 {
		batch = 64
	}
	signal, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(signal)

	saved := s.loadBookmark()
	bookmark, err := createBookmark(saved)
	if err != nil {
		return err
	}
	defer func() { evtClose(bookmark) }()

	channel, err := windows.UTF16PtrFromString(s.Channel)
	if err != nil {
		return err
	}
	q := s.Query
	if q == "" {
		q = "*"
	}
	query, err := windows.UTF16PtrFromString(q)
	if err != nil {
		return err
	}
	flags := uintptr(evtSubscribeToFutureEvents)
	var bm uintptr
	switch {
	case saved != "":
		flags, bm = evtSubscribeStartAfterBookmark, uintptr(bookmark)
	case s.FromOldest:
		flags = evtSubscribeStartAtOldestRecord
	}
	sub, _, callErr := procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(channel)), uintptr(unsafe.Pointer(query)), bm, 0, 0, flags)
	if sub == 0 {
		if errors.Is(callErr, errorEvtChannelNotFound) {
			return fmt.Errorf("winevt: channel %q not found", s.Channel)
		}
		return fmt.Errorf("EvtSubscribe(%s): %w", s.Channel, callErr)
	}
	defer evtClose(evtHandle(sub))

	handles := make([]evtHandle, batch)
	for {
		if ctx.Err() != nil {
			return nil
		}
		var returned uint32
		r, _, nextErr := procEvtNext.Call(sub, uintptr(batch), uintptr(unsafe.Pointer(&handles[0])), 0, 0, uintptr(unsafe.Pointer(&returned)))
		if r == 0 {
			if errors.Is(nextErr, errorNoMoreItems) || errors.Is(nextErr, errorInvalidOperation) {
				_ = windows.ResetEvent(signal)
				// Wait for new records, waking regularly to observe ctx.
				ev, _ := windows.WaitForSingleObject(signal, 500)
				_ = ev
				continue
			}
			return fmt.Errorf("EvtNext: %w", nextErr)
		}
		for i := uint32(0); i < returned; i++ {
			h := handles[i]
			xml, err := render(h, evtRenderEventXML)
			if err == nil {
				procEvtUpdateBookmark.Call(uintptr(bookmark), uintptr(h))
				bmXML, _ := render(bookmark, evtRenderBookmark)
				select {
				case out <- Event{Channel: s.Channel, XML: xml, Bookmark: bmXML}:
				case <-ctx.Done():
					evtCloseRange(handles[i:returned])
					return nil
				}
			}
			evtClose(h)
		}
	}
}

func evtCloseRange(hs []evtHandle) {
	for _, h := range hs {
		evtClose(h)
	}
}
