package listener

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestQueueListenerAcceptInjectAndClose(t *testing.T) {
	t.Parallel()

	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	l := NewQueueListener(addr, 0)
	if cap(l.conns) != 128 {
		t.Fatalf("cap(conns) = %d, want %d", cap(l.conns), 128)
	}
	if got := l.Addr(); got.String() != addr.String() {
		t.Fatalf("Addr() = %v, want %v", got, addr)
	}

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	if err := l.Inject(server); err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	accepted, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if accepted != server {
		t.Fatal("Accept() returned unexpected connection")
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() after Close() error = %v, want %v", err, net.ErrClosed)
	}
}

func TestQueueListenerInjectIntoClosedListenerClosesConn(t *testing.T) {
	t.Parallel()

	l := NewQueueListener(&net.TCPAddr{Port: 80}, 1)
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	conn := &stubConn{}

	err := l.Inject(conn)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Inject() error = %v, want %v", err, net.ErrClosed)
	}
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("Close() calls = %d, want %d", got, 1)
	}
}

func TestWrapConnUsesOverrideAddrs(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	local := stringAddr("local-override")
	remote := stringAddr("remote-override")
	conn := WrapConn(server, local, remote)

	if got := conn.LocalAddr().String(); got != "local-override" {
		t.Fatalf("LocalAddr() = %q, want %q", got, "local-override")
	}
	if got := conn.RemoteAddr().String(); got != "remote-override" {
		t.Fatalf("RemoteAddr() = %q, want %q", got, "remote-override")
	}
}

func TestWrapConnFallsBackToUnderlyingAddrs(t *testing.T) {
	t.Parallel()

	base := &stubConn{
		localAddr:  stringAddr("local-base"),
		remoteAddr: stringAddr("remote-base"),
	}
	conn := WrapConn(base, nil, nil)

	if got := conn.LocalAddr().String(); got != "local-base" {
		t.Fatalf("LocalAddr() = %q, want %q", got, "local-base")
	}
	if got := conn.RemoteAddr().String(); got != "remote-base" {
		t.Fatalf("RemoteAddr() = %q, want %q", got, "remote-base")
	}
}

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

type stubConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	closeCalls atomic.Int32
}

func (c *stubConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *stubConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *stubConn) Close() error                     { c.closeCalls.Add(1); return nil }
func (c *stubConn) LocalAddr() net.Addr              { return c.localAddr }
func (c *stubConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *stubConn) SetDeadline(time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }
