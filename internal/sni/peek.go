package sni

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/cryptobyte"
)

const (
	recordHeaderLen          = 5
	handshakeTypeClientHello = 1
	contentTypeHandshake     = 22
)

type ClientHelloInfo struct {
	ServerName string
	ALPN       []string
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func PeekClientHello(conn net.Conn, maxBytes int) (ClientHelloInfo, net.Conn, error) {
	var raw bytes.Buffer
	var handshake bytes.Buffer

	for raw.Len() < maxBytes {
		header := make([]byte, recordHeaderLen)
		if _, err := io.ReadFull(conn, header); err != nil {
			return ClientHelloInfo{}, nil, fmt.Errorf("read tls record header: %w", err)
		}
		raw.Write(header)

		if header[0] != contentTypeHandshake {
			return ClientHelloInfo{}, nil, fmt.Errorf("unexpected tls content type %d", header[0])
		}
		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if raw.Len()+recordLength > maxBytes {
			return ClientHelloInfo{}, nil, fmt.Errorf("client hello exceeded %d bytes", maxBytes)
		}
		payload := make([]byte, recordLength)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return ClientHelloInfo{}, nil, fmt.Errorf("read tls record payload: %w", err)
		}
		raw.Write(payload)
		handshake.Write(payload)

		info, done, err := parseClientHello(handshake.Bytes())
		if err != nil {
			return ClientHelloInfo{}, nil, err
		}
		if done {
			replay := &replayConn{
				Conn:   conn,
				reader: io.MultiReader(bytes.NewReader(raw.Bytes()), conn),
			}
			return info, replay, nil
		}
	}

	return ClientHelloInfo{}, nil, fmt.Errorf("client hello exceeded %d bytes", maxBytes)
}

func ParseClientHelloRecords(records []byte) (ClientHelloInfo, error) {
	var handshake bytes.Buffer
	remaining := records
	for len(remaining) > 0 {
		if len(remaining) < recordHeaderLen {
			return ClientHelloInfo{}, io.ErrUnexpectedEOF
		}
		header := remaining[:recordHeaderLen]
		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if len(remaining) < recordHeaderLen+recordLength {
			return ClientHelloInfo{}, io.ErrUnexpectedEOF
		}
		if header[0] != contentTypeHandshake {
			return ClientHelloInfo{}, fmt.Errorf("unexpected tls content type %d", header[0])
		}
		payload := remaining[recordHeaderLen : recordHeaderLen+recordLength]
		handshake.Write(payload)
		info, done, err := parseClientHello(handshake.Bytes())
		if err != nil {
			return ClientHelloInfo{}, err
		}
		if done {
			return info, nil
		}
		remaining = remaining[recordHeaderLen+recordLength:]
	}
	return ClientHelloInfo{}, io.ErrUnexpectedEOF
}

func parseClientHello(handshakeBytes []byte) (ClientHelloInfo, bool, error) {
	if len(handshakeBytes) < 4 {
		return ClientHelloInfo{}, false, nil
	}
	if handshakeBytes[0] != handshakeTypeClientHello {
		return ClientHelloInfo{}, false, fmt.Errorf("unexpected handshake type %d", handshakeBytes[0])
	}

	messageLen := int(handshakeBytes[1])<<16 | int(handshakeBytes[2])<<8 | int(handshakeBytes[3])
	if len(handshakeBytes) < 4+messageLen {
		return ClientHelloInfo{}, false, nil
	}

	message := cryptobyte.String(handshakeBytes[4 : 4+messageLen])
	var legacyVersion uint16
	var random []byte
	if !message.ReadUint16(&legacyVersion) || !message.ReadBytes(&random, 32) {
		return ClientHelloInfo{}, false, fmt.Errorf("malformed client hello preface")
	}

	var sessionID cryptobyte.String
	if !message.ReadUint8LengthPrefixed(&sessionID) {
		return ClientHelloInfo{}, false, fmt.Errorf("malformed session id")
	}
	var cipherSuites cryptobyte.String
	if !message.ReadUint16LengthPrefixed(&cipherSuites) {
		return ClientHelloInfo{}, false, fmt.Errorf("malformed cipher suites")
	}
	var compressionMethods cryptobyte.String
	if !message.ReadUint8LengthPrefixed(&compressionMethods) {
		return ClientHelloInfo{}, false, fmt.Errorf("malformed compression methods")
	}

	var info ClientHelloInfo
	if message.Empty() {
		return info, true, nil
	}

	var extensions cryptobyte.String
	if !message.ReadUint16LengthPrefixed(&extensions) {
		return ClientHelloInfo{}, false, fmt.Errorf("malformed extensions")
	}
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return ClientHelloInfo{}, false, fmt.Errorf("malformed extension block")
		}
		switch extType {
		case 0:
			serverName, err := parseServerName(extData)
			if err != nil {
				return ClientHelloInfo{}, false, err
			}
			info.ServerName = serverName
		case 16:
			alpn, err := parseALPN(extData)
			if err != nil {
				return ClientHelloInfo{}, false, err
			}
			info.ALPN = alpn
		}
	}
	return info, true, nil
}

func parseServerName(data cryptobyte.String) (string, error) {
	var serverNameList cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&serverNameList) {
		return "", fmt.Errorf("malformed sni extension")
	}
	for !serverNameList.Empty() {
		var nameType uint8
		var name cryptobyte.String
		if !serverNameList.ReadUint8(&nameType) || !serverNameList.ReadUint16LengthPrefixed(&name) {
			return "", fmt.Errorf("malformed server name entry")
		}
		if nameType == 0 {
			return string(name), nil
		}
	}
	return "", nil
}

func parseALPN(data cryptobyte.String) ([]string, error) {
	var protoList cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&protoList) {
		return nil, fmt.Errorf("malformed alpn extension")
	}
	var protos []string
	for !protoList.Empty() {
		var protoName cryptobyte.String
		if !protoList.ReadUint8LengthPrefixed(&protoName) {
			return nil, fmt.Errorf("malformed alpn protocol list")
		}
		protos = append(protos, string(protoName))
	}
	return protos, nil
}
