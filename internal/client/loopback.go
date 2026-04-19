package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"

	listenerpkg "github.com/define42/muxbridge-e2e/internal/listener"
)

const (
	loopbackPrefaceMagic   = "mbcl"
	loopbackPrefaceHdrSize = 6
	loopbackPrefaceMaxSize = 4 << 10
)

type loopbackListener struct {
	net.Listener
	logger *slog.Logger
}

func newLoopbackListener(base net.Listener, logger *slog.Logger) net.Listener {
	if logger == nil {
		logger = slog.Default()
	}
	return &loopbackListener{
		Listener: base,
		logger:   logger,
	}
}

func (l *loopbackListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		remoteAddr, err := readLoopbackPreface(conn)
		if err != nil {
			l.logger.Warn("read client loopback preface failed", "error", err)
			_ = conn.Close()
			continue
		}

		return listenerpkg.WrapConn(conn, nil, parseRemoteAddr(remoteAddr)), nil
	}
}

func writeLoopbackPreface(w io.Writer, remoteAddr string) error {
	if len(remoteAddr) > loopbackPrefaceMaxSize {
		return fmt.Errorf("loopback remote addr too long: %d", len(remoteAddr))
	}

	buf := make([]byte, loopbackPrefaceHdrSize+len(remoteAddr))
	copy(buf[:4], loopbackPrefaceMagic)
	binary.BigEndian.PutUint16(buf[4:loopbackPrefaceHdrSize], uint16(len(remoteAddr)))
	copy(buf[loopbackPrefaceHdrSize:], remoteAddr)
	return writeAll(w, buf)
}

func readLoopbackPreface(r io.Reader) (string, error) {
	var hdr [loopbackPrefaceHdrSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", fmt.Errorf("read loopback header: %w", err)
	}
	if string(hdr[:4]) != loopbackPrefaceMagic {
		return "", fmt.Errorf("invalid loopback preface magic %q", string(hdr[:4]))
	}

	size := int(binary.BigEndian.Uint16(hdr[4:loopbackPrefaceHdrSize]))
	if size > loopbackPrefaceMaxSize {
		return "", fmt.Errorf("loopback remote addr too large: %d", size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", fmt.Errorf("read loopback remote addr: %w", err)
	}
	return string(payload), nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}
