package client

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLoopbackPrefaceRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := writeLoopbackPreface(&buf, "192.0.2.10:443"); err != nil {
		t.Fatalf("writeLoopbackPreface() error = %v", err)
	}

	remoteAddr, err := readLoopbackPreface(&buf)
	if err != nil {
		t.Fatalf("readLoopbackPreface() error = %v", err)
	}
	if remoteAddr != "192.0.2.10:443" {
		t.Fatalf("remoteAddr = %q, want %q", remoteAddr, "192.0.2.10:443")
	}
}

func TestWriteLoopbackPrefaceRejectsOversizedRemoteAddr(t *testing.T) {
	t.Parallel()

	remoteAddr := string(bytes.Repeat([]byte("a"), loopbackPrefaceMaxSize+1))
	err := writeLoopbackPreface(io.Discard, remoteAddr)
	if err == nil || err.Error() == "" {
		t.Fatal("writeLoopbackPreface() error = nil, want oversize error")
	}
}

func TestReadLoopbackPrefaceErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "invalid magic",
			data: append([]byte("nope"), 0, 0),
			want: "invalid loopback preface magic",
		},
		{
			name: "oversized remote addr",
			data: oversizedLoopbackPreface(loopbackPrefaceMaxSize + 1),
			want: "loopback remote addr too large",
		},
		{
			name: "truncated remote addr",
			data: append(validLoopbackHeader(4), []byte("ip")...),
			want: "read loopback remote addr",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := readLoopbackPreface(bytes.NewReader(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("readLoopbackPreface() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestLoopbackListenerAcceptSkipsInvalidPreface(t *testing.T) {
	t.Parallel()

	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	loopbackListener := newLoopbackListener(baseListener, slogDiscard())
	defer func() { _ = loopbackListener.Close() }()

	type acceptResult struct {
		remoteAddr string
		err        error
	}
	results := make(chan acceptResult, 1)
	go func() {
		conn, err := loopbackListener.Accept()
		if err != nil {
			results <- acceptResult{err: err}
			return
		}
		defer func() { _ = conn.Close() }()
		results <- acceptResult{remoteAddr: conn.RemoteAddr().String()}
	}()

	badConn, err := net.Dial("tcp", loopbackListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial(bad) error = %v", err)
	}
	if _, err := badConn.Write([]byte("nope")); err != nil {
		t.Fatalf("Write(bad) error = %v", err)
	}
	_ = badConn.Close()

	goodConn, err := net.Dial("tcp", loopbackListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial(good) error = %v", err)
	}
	if err := writeLoopbackPreface(goodConn, "198.51.100.20:443"); err != nil {
		t.Fatalf("writeLoopbackPreface() error = %v", err)
	}
	_ = goodConn.Close()

	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("Accept() error = %v", result.err)
		}
		if result.remoteAddr != "198.51.100.20:443" {
			t.Fatalf("RemoteAddr() = %q, want %q", result.remoteAddr, "198.51.100.20:443")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept() did not return after valid preface")
	}
}

func validLoopbackHeader(size int) []byte {
	buf := make([]byte, loopbackPrefaceHdrSize)
	copy(buf[:4], loopbackPrefaceMagic)
	binary.BigEndian.PutUint16(buf[4:], uint16(size))
	return buf
}

func oversizedLoopbackPreface(size int) []byte {
	return append(validLoopbackHeader(size), byte('x'))
}
