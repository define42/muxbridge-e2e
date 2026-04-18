package control

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	controlpb "github.com/define42/muxbridge-e2e/proto"
)

func TestEnvelopeAndStreamHeaderRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewLockedWriter(&buf)

	env := &controlpb.Envelope{
		Message: &controlpb.Envelope_RegisterRequest{
			RegisterRequest: &controlpb.RegisterRequest{
				Token:     "demo-token",
				Hostnames: []string{"demo.example.test"},
				SessionId: "session-1",
			},
		},
	}
	if err := writer.WriteEnvelope(env); err != nil {
		t.Fatalf("WriteEnvelope() error = %v", err)
	}

	header := &controlpb.StreamHeader{
		Hostname:           "demo.example.test",
		RemoteAddr:         "127.0.0.1:12345",
		AcceptedAtUnixNano: 42,
	}
	if err := writer.WriteStreamHeader(header); err != nil {
		t.Fatalf("WriteStreamHeader() error = %v", err)
	}

	gotEnv, err := ReadEnvelope(&buf)
	if err != nil {
		t.Fatalf("ReadEnvelope() error = %v", err)
	}
	if gotEnv.GetRegisterRequest().GetToken() != "demo-token" {
		t.Fatalf("ReadEnvelope() token = %q, want %q", gotEnv.GetRegisterRequest().GetToken(), "demo-token")
	}

	gotHeader, err := ReadStreamHeader(&buf)
	if err != nil {
		t.Fatalf("ReadStreamHeader() error = %v", err)
	}
	if gotHeader.GetHostname() != "demo.example.test" {
		t.Fatalf("ReadStreamHeader() hostname = %q, want %q", gotHeader.GetHostname(), "demo.example.test")
	}
}

func TestReadEnvelopeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		wantErr string
	}{
		{
			name:    "empty frame",
			payload: appendFramePrefix(0, nil),
			wantErr: "empty control frame",
		},
		{
			name:    "frame too large",
			payload: appendFramePrefix(maxFrameSize+1, nil),
			wantErr: "control frame too large",
		},
		{
			name:    "short payload",
			payload: appendFramePrefix(5, []byte{1, 2}),
			wantErr: "unexpected EOF",
		},
		{
			name:    "invalid protobuf",
			payload: appendFramePrefix(1, []byte{0xff}),
			wantErr: "unmarshal frame",
		},
		{
			name:    "short header",
			payload: []byte{0, 0},
			wantErr: "unexpected EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ReadEnvelope(bytes.NewReader(tt.payload))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ReadEnvelope() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestWriteEnvelopeTooLarge(t *testing.T) {
	t.Parallel()

	env := &controlpb.Envelope{
		Message: &controlpb.Envelope_Error{
			Error: &controlpb.Error{Message: strings.Repeat("x", maxFrameSize)},
		},
	}

	err := WriteEnvelope(io.Discard, env)
	if err == nil || !strings.Contains(err.Error(), "control frame too large") {
		t.Fatalf("WriteEnvelope() error = %v, want too large error", err)
	}
}

func appendFramePrefix(length uint32, payload []byte) []byte {
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, length)
	return append(frame, payload...)
}
