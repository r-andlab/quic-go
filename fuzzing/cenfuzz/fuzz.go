package cenfuzz

import (
	"fmt"
	"net"
	"time"
	"crypto/tls"
	"io"
	"context"

	"github.com/r-andlab/quic-go/internal/protocol"
	"github.com/r-andlab/quic-go/internal/wire"
	"github.com/r-andlab/quic-go"
)

const version = protocol.Version1
const PrefixLen = 1

// Fuzz sends malformed QUIC headers to a real-world QUIC server via UDP and performs in-memory parsing checks.
func Fuzz(data []byte, targetHost string) ([]byte, error) {
	fmt.Println("this hit")
	if len(data) < PrefixLen {
		fmt.Println("data too short")
		return nil, fmt.Errorf("data too short")
	}

	connIDLen := int(data[0] % 21)
	data = data[PrefixLen:]

	// // Version Negotiation Packet
	// if wire.IsVersionNegotiationPacket(data) {
	// 	return fuzzVNP(data)
	// }

	connID, err := wire.ParseConnectionID(data, connIDLen)
	if err != nil {
		fmt.Println("invalid connection ID")
		return nil, fmt.Errorf("invalid connection ID: %w", err)
	}

	// // Short Header Packet
	// if !wire.IsLongHeaderPacket(data[0]) {
	// 	_, _ = wire.ParseShortHeader(data, connIDLen) // safe to ignore output for now
	// 	return sendToServer(data, targetHost)
	// }

	// Long Header
	is0RTTPacket := wire.Is0RTTPacket(data)
	hdr, _, _, err := wire.ParsePacket(data)
	if err != nil {
		fmt.Println("packet parse failed")
		return nil, fmt.Errorf("packet parse failed: %w", err)
	}

	if hdr.DestConnectionID != connID {
		fmt.Println("DCID mismatch:")
		return nil, fmt.Errorf("DCID mismatch: %s vs %s", hdr.DestConnectionID, connID)
	}
	if (hdr.Type == protocol.PacketType0RTT) != is0RTTPacket {
		fmt.Println("inconsistent 0-RTT packet detection")
		return nil, fmt.Errorf("inconsistent 0-RTT packet detection")
	}

	var extHdr *wire.ExtendedHeader
	if hdr.Type == protocol.PacketTypeRetry {
		extHdr = &wire.ExtendedHeader{Header: *hdr}
	} else {
		extHdr, err = hdr.ParseExtended(data)
		if err != nil {
			fmt.Println("failed to parse extended header")
			return nil, fmt.Errorf("failed to parse extended header: %w", err)
		}
	}

	if hdr.Length > 16383 {
		return SendToServer(data, targetHost)
	}

	b, err := extHdr.Append(nil, version)
	if err != nil {
		// If append fails due to conn ID length, consider non-fatal
		if hdr.DestConnectionID.Len() <= protocol.MaxConnIDLen && hdr.SrcConnectionID.Len() <= protocol.MaxConnIDLen {
			fmt.Println("append failed")
			return nil, fmt.Errorf("append failed: %w", err)
		}
		fmt.Println("Error most probable area")
		return nil, nil // packet not sent
	}

	if hdr.Type != protocol.PacketTypeRetry {
		expLen := extHdr.GetLength(version)
		if expLen != protocol.ByteCount(len(b)) {
			fmt.Println("inconsistent header length: expected")
			return nil, fmt.Errorf("inconsistent header length: expected %d, got %d", expLen, len(b))
		}
	}

	return SendToServer(data, targetHost)
}


func SendToServer(data []byte, targetHost string) ([]byte, error) {
	target := net.JoinHostPort(targetHost, "443")
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		fmt.Println("failed to resolve address ")
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println("failed to dial UDP")
		return nil, fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("failed to write packet")
		return nil, fmt.Errorf("failed to write packet: %w", err)
	}

	// Attempt to read server response
	buf := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	return buf[:n], nil
}

// func fuzzVNP(data []byte) int {
// 	connID, err := wire.ParseConnectionID(data, 0)
// 	if err != nil {
// 		return 0
// 	}
// 	dest, src, versions, err := wire.ParseVersionNegotiationPacket(data)
// 	if err != nil {
// 		return 0
// 	}
// 	if !bytes.Equal(dest, connID.Bytes()) {
// 		panic("connection IDs don't match")
// 	}
// 	if len(versions) == 0 {
// 		panic("no versions")
// 	}
// 	wire.ComposeVersionNegotiation(src, dest, versions)
// 	return sendToServer(data, "127.0.0.1") // Adjust this as needed
// }

// bad place for this function but I will find a better one later this is the function that will send a single packet that is unfuzzed the requested domain 
func SendInitialQUICPacket(target string) ([]byte, error) {
	// Resolve the target UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(target, "443"))
	if err != nil {
		fmt.Println("failed to resolve address")
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	// Bind a UDP socket locally
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		fmt.Println("failed to create UDP socket")
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer udpConn.Close()

	// Set up minimal TLS config (no cert verification)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	// Context with timeout for dialing
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Trigger QUIC handshake by dialing
	conn, err := quic.Dial(ctx, udpConn, udpAddr, tlsConf, nil)
	if err != nil {
		fmt.Println("dial error")
		return nil, fmt.Errorf("dial error: %w", err)
	}
	defer conn.CloseWithError(0, "done")

	// Open a bidirectional stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		fmt.Println("stream open error")
		return nil, fmt.Errorf("stream open error: %w", err)
	}
	defer stream.Close()

	// Attempt to read server response
	buf := make([]byte, 2048)
	stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		fmt.Println("read error")
		return nil, fmt.Errorf("read error: %w", err)
	}

	return buf[:n], nil
}