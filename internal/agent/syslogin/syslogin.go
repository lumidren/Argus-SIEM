// Package syslogin receives syslog over UDP, TCP and TLS (RFC 5426, 6587,
// 5425). Senders are checked against an allow-list of CIDRs; UDP is off
// unless explicitly configured (THREAT_MODEL T1.2).
package syslogin

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lumidren/argus/internal/syslog"
)

// Message is one received syslog frame.
type Message struct {
	Data      []byte
	Remote    string // ip:port of the sender
	Transport string // udp, tcp, tls
	Received  time.Time
}

// Allow is a CIDR allow-list; an empty list allows every sender.
type Allow struct{ prefixes []netip.Prefix }

// ParseAllow parses CIDRs or single addresses.
func ParseAllow(entries []string) (Allow, error) {
	var a Allow
	for _, s := range entries {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			addr, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return a, err
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		a.prefixes = append(a.prefixes, p.Masked())
	}
	return a, nil
}

// Permits reports whether addr may send.
func (a Allow) Permits(addr net.Addr) bool {
	if len(a.prefixes) == 0 {
		return true
	}
	var ip netip.Addr
	switch t := addr.(type) {
	case *net.UDPAddr:
		ip, _ = netip.AddrFromSlice(t.IP)
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(t.IP)
	default:
		ap, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return false
		}
		ip = ap.Addr()
	}
	ip = ip.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Server runs the configured listeners.
type Server struct {
	UDPAddr string
	TCPAddr string
	TLSAddr string
	TLS     *tls.Config
	Allow   Allow
	Log     *slog.Logger
	// MaxConns bounds concurrent TCP/TLS connections.
	MaxConns int
	// IdleTimeout closes stream connections with no data.
	IdleTimeout time.Duration

	mu        sync.Mutex
	listeners []net.Listener
	pc        net.PacketConn
	rejected  int64
}

// Rejected returns how many senders were refused by the allow-list.
func (s *Server) Rejected() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rejected
}

func (s *Server) reject(addr net.Addr) {
	s.mu.Lock()
	s.rejected++
	s.mu.Unlock()
	if s.Log != nil {
		s.Log.Warn("syslog sender not in allow-list", "remote", addr.String())
	}
}

// Addrs returns the bound addresses (useful with ":0").
func (s *Server) Addrs() (udp, tcp, tlsAddr net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pc != nil {
		udp = s.pc.LocalAddr()
	}
	for i, l := range s.listeners {
		if i == 0 && s.TCPAddr != "" {
			tcp = l.Addr()
		} else {
			tlsAddr = l.Addr()
		}
	}
	return
}

// Start binds the listeners and serves until ctx ends. Received frames are
// sent to out; when out is full the sender is back-pressured (TCP) or the
// datagram is dropped after a short wait (UDP).
func (s *Server) Start(ctx context.Context, out chan<- Message) error {
	if s.UDPAddr == "" && s.TCPAddr == "" && s.TLSAddr == "" {
		return errors.New("syslogin: no listener configured")
	}
	if s.MaxConns <= 0 {
		s.MaxConns = 512
	}
	if s.IdleTimeout <= 0 {
		s.IdleTimeout = 5 * time.Minute
	}
	var wg sync.WaitGroup
	if s.UDPAddr != "" {
		pc, err := net.ListenPacket("udp", s.UDPAddr)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.pc = pc
		s.mu.Unlock()
		wg.Add(1)
		go func() { defer wg.Done(); s.serveUDP(ctx, pc, out) }()
	}
	sem := make(chan struct{}, s.MaxConns)
	for _, spec := range []struct {
		addr      string
		tls       bool
		transport string
	}{{s.TCPAddr, false, "tcp"}, {s.TLSAddr, true, "tls"}} {
		if spec.addr == "" {
			continue
		}
		var l net.Listener
		var err error
		if spec.tls {
			if s.TLS == nil {
				return errors.New("syslogin: TLS listener needs a certificate")
			}
			l, err = tls.Listen("tcp", spec.addr, s.TLS)
		} else {
			l, err = net.Listen("tcp", spec.addr)
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.listeners = append(s.listeners, l)
		s.mu.Unlock()
		transport := spec.transport
		wg.Add(1)
		go func() { defer wg.Done(); s.serveStream(ctx, l, transport, sem, out) }()
	}
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		if s.pc != nil {
			s.pc.Close()
		}
		for _, l := range s.listeners {
			l.Close()
		}
		s.mu.Unlock()
	}()
	wg.Wait()
	return nil
}

func (s *Server) serveUDP(ctx context.Context, pc net.PacketConn, out chan<- Message) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if !s.Allow.Permits(addr) {
			s.reject(addr)
			continue
		}
		msg := Message{Data: append([]byte(nil), buf[:n]...), Remote: addr.String(), Transport: "udp", Received: time.Now().UTC()}
		select {
		case out <- msg:
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
			// UDP has no back-pressure; dropping is the only option.
		}
	}
}

func (s *Server) serveStream(ctx context.Context, l net.Listener, transport string, sem chan struct{}, out chan<- Message) {
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if !s.Allow.Permits(c.RemoteAddr()) {
			s.reject(c.RemoteAddr())
			c.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close() // over the connection limit
			continue
		}
		go func() {
			defer func() { <-sem }()
			s.handleConn(ctx, c, transport, out)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context, c net.Conn, transport string, out chan<- Message) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	r := bufio.NewReaderSize(c, 64<<10)
	var buf []byte
	tmp := make([]byte, 32<<10)
	for {
		_ = c.SetReadDeadline(time.Now().Add(s.IdleTimeout))
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				msg, consumed, ok, ferr := syslog.Frame(buf)
				if ferr != nil {
					return // oversize frame: drop the connection
				}
				if !ok {
					break
				}
				buf = buf[consumed:]
				if len(msg) == 0 {
					continue
				}
				m := Message{Data: append([]byte(nil), msg...), Remote: c.RemoteAddr().String(), Transport: transport, Received: time.Now().UTC()}
				select {
				case out <- m:
				case <-ctx.Done():
					return
				}
			}
		}
		if err != nil {
			// A final unterminated line is delivered on clean close.
			if len(buf) > 0 && ctx.Err() == nil {
				select {
				case out <- Message{Data: append([]byte(nil), buf...), Remote: c.RemoteAddr().String(), Transport: transport, Received: time.Now().UTC()}:
				case <-ctx.Done():
				}
			}
			return
		}
	}
}
