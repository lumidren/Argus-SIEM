package syslogin

import (
	"context"
	"net"
	"testing"
	"time"
)

func startServer(t *testing.T, s *Server) (chan Message, context.CancelFunc) {
	t.Helper()
	out := make(chan Message, 100)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Start(ctx, out) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		u, tc, _ := s.Addrs()
		if (s.UDPAddr == "" || u != nil) && (s.TCPAddr == "" || tc != nil) {
			return out, cancel
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	t.Fatal("listeners did not start")
	return nil, nil
}

func next(t *testing.T, ch chan Message) Message {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("no message")
	}
	return Message{}
}

func TestTCPFramingAndUDP(t *testing.T) {
	s := &Server{UDPAddr: "127.0.0.1:0", TCPAddr: "127.0.0.1:0"}
	out, cancel := startServer(t, s)
	defer cancel()
	udp, tcp, _ := s.Addrs()

	c, err := net.Dial("tcp", tcp.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("<34>1 - host app - - - newline framed\n"))
	_, _ = c.Write([]byte("23 <34>1 - - - - - - octet"))
	_, _ = c.Write([]byte("<34>unterminated tail"))
	c.Close()
	for _, want := range []string{"<34>1 - host app - - - newline framed", "<34>1 - - - - - - octet", "<34>unterminated tail"} {
		if m := next(t, out); string(m.Data) != want || m.Transport != "tcp" {
			t.Fatalf("got %q (%s), want %q", m.Data, m.Transport, want)
		}
	}

	uc, err := net.Dial("udp", udp.String())
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	_, _ = uc.Write([]byte("<13>Jun  1 09:00:00 h app: over udp"))
	if m := next(t, out); string(m.Data) != "<13>Jun  1 09:00:00 h app: over udp" || m.Transport != "udp" {
		t.Fatalf("udp: %q", m.Data)
	}
}

func TestAllowList(t *testing.T) {
	a, err := ParseAllow([]string{"10.0.0.0/8", "192.0.2.7"})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Permits(&net.TCPAddr{IP: net.ParseIP("10.1.2.3")}) || !a.Permits(&net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.7")}) {
		t.Fatal("allowed senders refused")
	}
	if a.Permits(&net.TCPAddr{IP: net.ParseIP("192.0.2.8")}) {
		t.Fatal("unlisted sender permitted")
	}
	if _, err := ParseAllow([]string{"not-an-ip"}); err == nil {
		t.Fatal("bad entry accepted")
	}

	deny, _ := ParseAllow([]string{"203.0.113.0/24"})
	s := &Server{TCPAddr: "127.0.0.1:0", Allow: deny}
	out, cancel := startServer(t, s)
	defer cancel()
	_, tcp, _ := s.Addrs()
	c, err := net.Dial("tcp", tcp.String())
	if err == nil {
		_, _ = c.Write([]byte("<34>refused\n"))
		c.Close()
	}
	select {
	case m := <-out:
		t.Fatalf("message from refused sender delivered: %q", m.Data)
	case <-time.After(200 * time.Millisecond):
	}
	if s.Rejected() == 0 {
		t.Fatal("rejection not counted")
	}
}

func TestNoListeners(t *testing.T) {
	if err := (&Server{}).Start(context.Background(), make(chan Message)); err == nil {
		t.Fatal("expected configuration error")
	}
	if err := (&Server{TLSAddr: "127.0.0.1:0"}).Start(context.Background(), make(chan Message)); err == nil {
		t.Fatal("TLS without certificate must fail")
	}
}
