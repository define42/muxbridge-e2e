package sni

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestParseClientHelloRecords(t *testing.T) {
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
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

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
	records := buildClientHelloRecords(t, "demo.example.com", []string{"h2"}, false)
	records = records[:len(records)-1]
	if _, err := ParseClientHelloRecords(records); err == nil {
		t.Fatal("expected error for malformed client hello")
	}
}

func buildClientHelloRecords(t *testing.T, sni string, alpn []string, fragmented bool) []byte {
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
	writeUint16(&body, uint16(extensions.Len()))
	body.Write(extensions.Bytes())

	hello := append([]byte{handshakeTypeClientHello}, uint24(body.Len())...)
	hello = append(hello, body.Bytes()...)

	if !fragmented {
		return appendRecord(hello)
	}
	mid := len(hello) / 2
	var records []byte
	records = append(records, appendRecord(hello[:mid])...)
	records = append(records, appendRecord(hello[mid:])...)
	return records
}

func appendRecord(payload []byte) []byte {
	record := make([]byte, 0, recordHeaderLen+len(payload))
	record = append(record, contentTypeHandshake, 0x03, 0x03)
	record = binary.BigEndian.AppendUint16(record, uint16(len(payload)))
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
