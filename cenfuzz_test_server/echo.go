package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"math/big"

	"github.com/r-andlab/quic-go"
)

const addr = "localhost:4242"

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}

func main() {
	if err := echoServer(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Println("QUIC Echo Server is running on", addr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Connection error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "closing")

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Stream accept error: %v", err)
		return
	}
	defer stream.Close()

	_, err = io.Copy(loggingWriter{stream}, stream)
	if err != nil {
		log.Printf("Stream copy error: %v", err)
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  priv,
		}},
		NextProtos: []string{"quic-echo-example"},
	}
}
