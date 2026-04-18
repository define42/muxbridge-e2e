package control

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"google.golang.org/protobuf/proto"

	controlpb "github.com/define42/muxbridge-e2e/proto"
)

const maxFrameSize = 1 << 20

const ALPNControl = "muxbridge-control/1"

type LockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func NewLockedWriter(w io.Writer) *LockedWriter {
	return &LockedWriter{w: w}
}

func (l *LockedWriter) WriteEnvelope(env *controlpb.Envelope) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return WriteEnvelope(l.w, env)
}

func (l *LockedWriter) WriteStreamHeader(header *controlpb.StreamHeader) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return WriteStreamHeader(l.w, header)
}

func ReadEnvelope(r io.Reader) (*controlpb.Envelope, error) {
	var env controlpb.Envelope
	if err := readFrame(r, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

func WriteEnvelope(w io.Writer, env *controlpb.Envelope) error {
	return writeFrame(w, env)
}

func ReadStreamHeader(r io.Reader) (*controlpb.StreamHeader, error) {
	var header controlpb.StreamHeader
	if err := readFrame(r, &header); err != nil {
		return nil, err
	}
	return &header, nil
}

func WriteStreamHeader(w io.Writer, header *controlpb.StreamHeader) error {
	return writeFrame(w, header)
}

func readFrame(r io.Reader, msg proto.Message) error {
	var lengthBuf [4]byte
	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(lengthBuf[:])
	if length == 0 {
		return fmt.Errorf("empty control frame")
	}
	if length > maxFrameSize {
		return fmt.Errorf("control frame too large: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	if err := proto.Unmarshal(payload, msg); err != nil {
		return fmt.Errorf("unmarshal frame: %w", err)
	}
	return nil
}

func writeFrame(w io.Writer, msg proto.Message) error {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	if len(payload) > maxFrameSize {
		return fmt.Errorf("control frame too large: %d", len(payload))
	}
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(payload)))
	if _, err := w.Write(lengthBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}
