package sni

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

func TestParseClientHelloRecords(t *testing.T) {
	t.Parallel()

	records := buildClientHelloRecords(t, "demo.example.com", []string{"h2", "http/1.1"}, false)
	info, err := ParseClientHelloRecords(records)
	if err != nil {
		t.Fatalf("ParseClientHelloRecords() error = %v", err)
	}
	if info.ServerName != "demo.example.com" {
		t.Fatalf("ServerName = %q, want %q", info.ServerName, "demo.example.com")
	}
	if len(info.ALPN) != 2 || info.ALPN[0] != "h2" || info.ALPN[1] != "http/1.1" {
		t.Fatalf("ALPN = %#v", info.ALPN)
	}
}

func TestParseClientHelloRecordsFragmented(t *testing.T) {
	t.Parallel()

	records := buildClientHelloRecords(t, "demo.example.com", []string{"acme-tls/1"}, true)
	info, err := ParseClientHelloRecords(records)
	if err != nil {
		t.Fatalf("ParseClientHelloRecords() error = %v", err)
	}
	if info.ServerName != "demo.example.com" {
		t.Fatalf("ServerName = %q", info.ServerName)
	}
	if got := len(info.ALPN); got != 1 || info.ALPN[0] != "acme-tls/1" {
		t.Fatalf("ALPN = %#v", info.ALPN)
	}
}

func TestPeekClientHelloReplay(t *testing.T) {
	t.Parallel()

	server, client := net.Pipe()
	defer func() {
		_ = server.Close()
	}()
	defer func() {
		_ = client.Close()
	}()

	records := buildClientHelloRecords(t, "demo.example.com", []string{"h2"}, true)
	extra := []byte("payload-after-clienthello")

	go func() {
		_, _ = client.Write(append(records, extra...))
		_ = client.Close()
	}()

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	info, replay, err := PeekClientHello(server, 64<<10)
	if err != nil {
		t.Fatalf("PeekClientHello() error = %v", err)
	}
	if info.ServerName != "demo.example.com" {
		t.Fatalf("ServerName = %q", info.ServerName)
	}
	if err := replay.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	got, err := io.ReadAll(replay)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	want := append(append([]byte(nil), records...), extra...)
	if !bytes.Equal(got, want) {
		t.Fatalf("replayed bytes mismatch")
	}
}

func TestParseClientHelloRecordsMissingSNI(t *testing.T) {
	t.Parallel()

	records := buildClientHelloRecords(t, "", []string{"h2"}, false)
	info, err := ParseClientHelloRecords(records)
	if err != nil {
		t.Fatalf("ParseClientHelloRecords() error = %v", err)
	}
	if info.ServerName != "" {
		t.Fatalf("ServerName = %q, want empty", info.ServerName)
	}
}

func TestParseClientHelloRecordsMalformed(t *testing.T) {
	t.Parallel()

	records := buildClientHelloRecords(t, "demo.example.com", []string{"h2"}, false)
	records = records[:len(records)-1]
	if _, err := ParseClientHelloRecords(records); err == nil {
		t.Fatal("expected error for malformed client hello")
	}
}

func TestPeekClientHelloErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		payload  []byte
		maxBytes int
		wantErr  string
	}{
		{
			name:     "short header",
			payload:  []byte{contentTypeHandshake, 0x03},
			maxBytes: 64 << 10,
			wantErr:  "read tls record header",
		},
		{
			name:     "unexpected content type",
			payload:  appendTLSRecord(23, nil),
			maxBytes: 64 << 10,
			wantErr:  "unexpected tls content type 23",
		},
		{
			name:     "record exceeds max bytes",
			payload:  appendTLSRecord(contentTypeHandshake, nil),
			maxBytes: 4,
			wantErr:  "client hello exceeded 4 bytes",
		},
		{
			name:     "short payload",
			payload:  appendTLSRecordWithDeclaredLength(contentTypeHandshake, 5, []byte{1, 2}),
			maxBytes: 64 << 10,
			wantErr:  "read tls record payload",
		},
		{
			name:     "unexpected handshake type",
			payload:  appendRecord([]byte{2, 0, 0, 0}),
			maxBytes: 64 << 10,
			wantErr:  "unexpected handshake type 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := peekClientHelloFromBytes(t, tt.payload, tt.maxBytes)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("PeekClientHello() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseClientHelloRecordsErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		records []byte
		wantErr error
		wantMsg string
	}{
		{
			name:    "short record header",
			records: []byte{contentTypeHandshake},
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "short record payload",
			records: appendTLSRecordWithDeclaredLength(contentTypeHandshake, 3, []byte{1}),
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "unexpected content type",
			records: appendTLSRecord(23, nil),
			wantMsg: "unexpected tls content type 23",
		},
		{
			name:    "incomplete client hello payload",
			records: appendRecord([]byte{handshakeTypeClientHello, 0, 0, 5, 0}),
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "unexpected handshake type",
			records: appendRecord([]byte{2, 0, 0, 0}),
			wantMsg: "unexpected handshake type 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseClientHelloRecords(tt.records)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseClientHelloRecords() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("ParseClientHelloRecords() error = %v, want substring %q", err, tt.wantMsg)
			}
		})
	}
}

func TestParseClientHelloNoExtensions(t *testing.T) {
	t.Parallel()

	handshake := buildClientHelloHandshake(t, "", nil, false)
	info, done, err := parseClientHello(handshake)
	if err != nil {
		t.Fatalf("parseClientHello() error = %v", err)
	}
	if !done {
		t.Fatal("parseClientHello() done = false, want true")
	}
	if info.ServerName != "" || len(info.ALPN) != 0 {
		t.Fatalf("parseClientHello() info = %#v, want empty result", info)
	}
}

func TestParseClientHelloMalformedSections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		handshake []byte
		wantDone  bool
		wantErr   string
	}{
		{
			name:      "short header",
			handshake: []byte{handshakeTypeClientHello, 0, 0},
			wantDone:  false,
		},
		{
			name:      "incomplete message",
			handshake: []byte{handshakeTypeClientHello, 0, 0, 5, 0},
			wantDone:  false,
		},
		{
			name:      "malformed preface",
			handshake: []byte{handshakeTypeClientHello, 0, 0, 1, 0},
			wantErr:   "malformed client hello preface",
		},
		{
			name:      "malformed session id",
			handshake: minimalClientHelloWithBodyLen(t, 34),
			wantErr:   "malformed session id",
		},
		{
			name:      "malformed cipher suites",
			handshake: minimalClientHelloWithBodyLen(t, 35),
			wantErr:   "malformed cipher suites",
		},
		{
			name:      "malformed compression methods",
			handshake: minimalClientHelloWithBodyLen(t, 37),
			wantErr:   "malformed compression methods",
		},
		{
			name:      "malformed extensions",
			handshake: clientHelloFromBody(append(minimalClientHelloBody(39), 0xff)),
			wantErr:   "malformed extensions",
		},
		{
			name:      "malformed extension block",
			handshake: clientHelloFromBody(append(minimalClientHelloBody(38), 0x00, 0x01, 0xff)),
			wantErr:   "malformed extension block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, done, err := parseClientHello(tt.handshake)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("parseClientHello() error = %v", err)
				}
				if done != tt.wantDone {
					t.Fatalf("parseClientHello() done = %v, want %v", done, tt.wantDone)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseClientHello() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseServerNameCases(t *testing.T) {
	t.Parallel()

	valid := buildServerNameExtension(
		serverNameEntry{nameType: 1, name: "ignored.example.com"},
		serverNameEntry{nameType: 0, name: "demo.example.com"},
	)
	serverName, err := parseServerName(cryptobyte.String(valid))
	if err != nil {
		t.Fatalf("parseServerName(valid) error = %v", err)
	}
	if serverName != "demo.example.com" {
		t.Fatalf("parseServerName(valid) = %q, want %q", serverName, "demo.example.com")
	}

	nonHostOnly := buildServerNameExtension(serverNameEntry{nameType: 1, name: "ignored.example.com"})
	serverName, err = parseServerName(cryptobyte.String(nonHostOnly))
	if err != nil {
		t.Fatalf("parseServerName(non-host) error = %v", err)
	}
	if serverName != "" {
		t.Fatalf("parseServerName(non-host) = %q, want empty", serverName)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "malformed extension",
			data:    []byte{0x00},
			wantErr: "malformed sni extension",
		},
		{
			name:    "malformed entry",
			data:    []byte{0x00, 0x01, 0x00},
			wantErr: "malformed server name entry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseServerName(cryptobyte.String(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseServerName() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseALPNErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "malformed extension",
			data:    []byte{0x00},
			wantErr: "malformed alpn extension",
		},
		{
			name:    "malformed protocol list",
			data:    []byte{0x00, 0x02, 0x02, 'h'},
			wantErr: "malformed alpn protocol list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseALPN(cryptobyte.String(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseALPN() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func buildClientHelloRecords(t *testing.T, sni string, alpn []string, fragmented bool) []byte {
	t.Helper()

	hello := buildClientHelloHandshake(t, sni, alpn, true)
	if !fragmented {
		return appendRecord(hello)
	}
	mid := len(hello) / 2
	var records []byte
	records = append(records, appendRecord(hello[:mid])...)
	records = append(records, appendRecord(hello[mid:])...)
	return records
}

func buildClientHelloHandshake(t *testing.T, sni string, alpn []string, includeExtensionsLength bool) []byte {
	t.Helper()

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	body.Write(random)
	body.WriteByte(0)

	ciphers := []byte{0x00, 0x02, 0x13, 0x01}
	body.Write(ciphers)
	body.Write([]byte{0x01, 0x00})

	var extensions bytes.Buffer
	if sni != "" {
		var sniData bytes.Buffer
		name := []byte(sni)
		writeUint16(&sniData, uint16(1+2+len(name)))
		sniData.WriteByte(0)
		writeUint16(&sniData, uint16(len(name)))
		sniData.Write(name)
		writeExtension(&extensions, 0, sniData.Bytes())
	}
	if len(alpn) > 0 {
		var alpnList bytes.Buffer
		for _, proto := range alpn {
			alpnList.WriteByte(byte(len(proto)))
			alpnList.WriteString(proto)
		}
		var alpnData bytes.Buffer
		writeUint16(&alpnData, uint16(alpnList.Len()))
		alpnData.Write(alpnList.Bytes())
		writeExtension(&extensions, 16, alpnData.Bytes())
	}
	if includeExtensionsLength {
		writeUint16(&body, uint16(extensions.Len()))
		body.Write(extensions.Bytes())
	}

	hello := append([]byte{handshakeTypeClientHello}, uint24(body.Len())...)
	hello = append(hello, body.Bytes()...)
	return hello
}

func minimalClientHelloWithBodyLen(t *testing.T, bodyLen int) []byte {
	t.Helper()

	return clientHelloFromBody(minimalClientHelloBody(bodyLen))
}

func minimalClientHelloBody(bodyLen int) []byte {
	body := make([]byte, bodyLen)
	if bodyLen >= 2 {
		body[0], body[1] = 0x03, 0x03
	}
	return body
}

func clientHelloFromBody(body []byte) []byte {
	return append([]byte{handshakeTypeClientHello}, append(uint24(len(body)), body...)...)
}

func appendRecord(payload []byte) []byte {
	return appendTLSRecord(contentTypeHandshake, payload)
}

func appendTLSRecord(contentType byte, payload []byte) []byte {
	record := make([]byte, 0, recordHeaderLen+len(payload))
	record = append(record, contentType, 0x03, 0x03)
	record = binary.BigEndian.AppendUint16(record, uint16(len(payload)))
	record = append(record, payload...)
	return record
}

func appendTLSRecordWithDeclaredLength(contentType byte, declaredLength uint16, payload []byte) []byte {
	record := make([]byte, 0, recordHeaderLen+len(payload))
	record = append(record, contentType, 0x03, 0x03)
	record = binary.BigEndian.AppendUint16(record, declaredLength)
	record = append(record, payload...)
	return record
}

func writeExtension(buf *bytes.Buffer, extType uint16, data []byte) {
	writeUint16(buf, extType)
	writeUint16(buf, uint16(len(data)))
	buf.Write(data)
}

func writeUint16(buf *bytes.Buffer, v uint16) {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], v)
	buf.Write(tmp[:])
}

func uint24(n int) []byte {
	return []byte{byte(n >> 16), byte(n >> 8), byte(n)}
}

func peekClientHelloFromBytes(t *testing.T, payload []byte, maxBytes int) (ClientHelloInfo, net.Conn, error) {
	t.Helper()

	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	go func() {
		_, _ = client.Write(payload)
		_ = client.Close()
	}()

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	return PeekClientHello(server, maxBytes)
}

type serverNameEntry struct {
	nameType uint8
	name     string
}

func buildServerNameExtension(entries ...serverNameEntry) []byte {
	var serverNameList bytes.Buffer
	for _, entry := range entries {
		serverNameList.WriteByte(entry.nameType)
		writeUint16(&serverNameList, uint16(len(entry.name)))
		serverNameList.WriteString(entry.name)
	}

	var ext bytes.Buffer
	writeUint16(&ext, uint16(serverNameList.Len()))
	ext.Write(serverNameList.Bytes())
	return ext.Bytes()
}
