package header

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/r-andlab/quic-go/internal/protocol"
	"github.com/r-andlab/quic-go/internal/wire"
)

const version = protocol.Version1
const PrefixLen = 1

// Fuzz sends malformed QUIC headers to a real-world QUIC server via UDP and performs in-memory parsing checks.
func Fuzz(data []byte, targetHost string) int {
	if len(data) < PrefixLen {
		return 0
	}
	connIDLen := int(data[0] % 21)
	data = data[PrefixLen:]

	if wire.IsVersionNegotiationPacket(data) {
		return fuzzVNP(data)
	}

	connID, err := wire.ParseConnectionID(data, connIDLen)
	if err != nil {
		return 0
	}

	if !wire.IsLongHeaderPacket(data[0]) {
		wire.ParseShortHeader(data, connIDLen)
		return sendToServer(data, targetHost)
	}

	is0RTTPacket := wire.Is0RTTPacket(data)
	hdr, _, _, err := wire.ParsePacket(data)
	if err != nil {
		return 0
	}
	if hdr.DestConnectionID != connID {
		panic(fmt.Sprintf("Expected connection IDs to match: %s vs %s", hdr.DestConnectionID, connID))
	}
	if (hdr.Type == protocol.PacketType0RTT) != is0RTTPacket {
		panic("inconsistent 0-RTT packet detection")
	}

	var extHdr *wire.ExtendedHeader
	if hdr.Type == protocol.PacketTypeRetry {
		extHdr = &wire.ExtendedHeader{Header: *hdr}
	} else {
		extHdr, err = hdr.ParseExtended(data)
		if err != nil {
			return 0
		}
	}

	if hdr.Length > 16383 {
		return sendToServer(data, targetHost)
	}

	b, err := extHdr.Append(nil, version)
	if err != nil {
		if hdr.DestConnectionID.Len() <= protocol.MaxConnIDLen && hdr.SrcConnectionID.Len() <= protocol.MaxConnIDLen {
			panic(err)
		}
		return 0
	}

	if hdr.Type != protocol.PacketTypeRetry {
		expLen := extHdr.GetLength(version)
		if expLen != protocol.ByteCount(len(b)) {
			panic(fmt.Sprintf("inconsistent header length: %#v. Expected %d, got %d", extHdr, expLen, len(b)))
		}
	}

	return sendToServer(data, targetHost)
}

func sendToServer(data []byte, targetHost string) int {
	target := net.JoinHostPort(targetHost, "443")
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		fmt.Println("Failed to resolve address:", err)
		return 0
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println("Failed to dial UDP:", err)
		return 0
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("Failed to write packet:", err)
		return 0
	}

	buf := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, _, err := conn.ReadFrom(buf)
	if err == nil && n > 0 {
		fmt.Printf("Received %d bytes in response\n", n)
	}
	return 1
}

func fuzzVNP(data []byte) int {
	connID, err := wire.ParseConnectionID(data, 0)
	if err != nil {
		return 0
	}
	dest, src, versions, err := wire.ParseVersionNegotiationPacket(data)
	if err != nil {
		return 0
	}
	if !bytes.Equal(dest, connID.Bytes()) {
		panic("connection IDs don't match")
	}
	if len(versions) == 0 {
		panic("no versions")
	}
	wire.ComposeVersionNegotiation(src, dest, versions)
	return sendToServer(data, "127.0.0.1") // Adjust this as needed
}