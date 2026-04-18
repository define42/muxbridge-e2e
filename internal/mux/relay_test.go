package mux

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestRelayCopiesBothDirectionsAndClosesWriters(t *testing.T) {
	t.Parallel()

	clientSide := &scriptConn{reader: bytes.NewReader([]byte("hello"))}
	upstreamSide := &scriptConn{reader: bytes.NewReader([]byte("world"))}

	result := Relay(clientSide, upstreamSide)

	if got := result.ClientToUpstream; got != int64(len("hello")) {
		t.Fatalf("ClientToUpstream = %d, want %d", got, len("hello"))
	}
	if got := result.UpstreamToClient; got != int64(len("world")) {
		t.Fatalf("UpstreamToClient = %d, want %d", got, len("world"))
	}
	if got := upstreamSide.writes.String(); got != "hello" {
		t.Fatalf("upstream writes = %q, want %q", got, "hello")
	}
	if got := clientSide.writes.String(); got != "world" {
		t.Fatalf("client writes = %q, want %q", got, "world")
	}
	if got := clientSide.closeCalls.Load(); got != 1 {
		t.Fatalf("client Close() calls = %d, want %d", got, 1)
	}
	if got := upstreamSide.closeCalls.Load(); got != 1 {
		t.Fatalf("upstream Close() calls = %d, want %d", got, 1)
	}
	if got := clientSide.closeWriteCalls.Load(); got != 1 {
		t.Fatalf("client CloseWrite() calls = %d, want %d", got, 1)
	}
	if got := upstreamSide.closeWriteCalls.Load(); got != 1 {
		t.Fatalf("upstream CloseWrite() calls = %d, want %d", got, 1)
	}
}

func TestCopyAndCloseReturnsCopyError(t *testing.T) {
	t.Parallel()

	dst := &scriptConn{reader: bytes.NewReader(nil)}
	src := &scriptConn{reader: errorReader{err: errors.New("boom")}}

	n, err := copyAndClose(dst, src)
	if n != 0 {
		t.Fatalf("copyAndClose() bytes = %d, want %d", n, 0)
	}
	if err == nil || err.Error() != "boom" {
		t.Fatalf("copyAndClose() error = %v, want %q", err, "boom")
	}
	if got := dst.closeWriteCalls.Load(); got != 1 {
		t.Fatalf("CloseWrite() calls = %d, want %d", got, 1)
	}
}

type scriptConn struct {
	reader io.Reader
	writes bytes.Buffer

	closeCalls      atomic.Int32
	closeWriteCalls atomic.Int32
}

func (c *scriptConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *scriptConn) Write(p []byte) (int, error) {
	return c.writes.Write(p)
}

func (c *scriptConn) Close() error {
	c.closeCalls.Add(1)
	return nil
}

func (c *scriptConn) CloseWrite() error {
	c.closeWriteCalls.Add(1)
	return nil
}

func (c *scriptConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *scriptConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }
