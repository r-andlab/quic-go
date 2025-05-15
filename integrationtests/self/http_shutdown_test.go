package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/r-andlab/quic-go/http3"
	quicproxy "github.com/r-andlab/quic-go/integrationtests/tools/proxy"

	"github.com/stretchr/testify/require"
)

func TestHTTPShutdown(t *testing.T) {
	mux := http.NewServeMux()
	var server *http3.Server
	port := startHTTPServer(t, mux, func(s *http3.Server) { server = s })
	client := newHTTP3Client(t)

	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		go func() {
			require.NoError(t, server.Close())
		}()
		time.Sleep(scaleDuration(10 * time.Millisecond)) // make sure the server started shutting down
	})

	_, err := client.Get(fmt.Sprintf("https://localhost:%d/shutdown", port))
	require.Error(t, err)
	var appErr *http3.Error
	require.ErrorAs(t, err, &appErr)
	require.Equal(t, http3.ErrCodeNoError, appErr.ErrorCode)
}

func TestGracefulShutdownShortRequest(t *testing.T) {
	delay := scaleDuration(25 * time.Millisecond)

	var server *http3.Server
	mux := http.NewServeMux()
	port := startHTTPServer(t, mux, func(s *http3.Server) { server = s })
	errChan := make(chan error, 1)
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		go func() {
			defer close(errChan)
			errChan <- server.Shutdown(context.Background())
		}()
		time.Sleep(delay)
		w.Write([]byte("shutdown"))
	})

	client := newHTTP3Client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*delay)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/shutdown", port), nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, []byte("shutdown"), body)
	client.Transport.(*http3.Transport).Close() // manually close the client

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not complete")
	}
}

func TestGracefulShutdownLongLivedRequest(t *testing.T) {
	delay := scaleDuration(25 * time.Millisecond)
	errChan := make(chan error, 1)
	requestChan := make(chan time.Duration, 1)

	var server *http3.Server
	mux := http.NewServeMux()
	port := startHTTPServer(t, mux, func(s *http3.Server) { server = s })
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), delay)
			defer cancel()
			errChan <- server.Shutdown(ctx)
		}()

		// measure how long it takes until the request errors
		for t := range time.NewTicker(delay / 10).C {
			if _, err := w.Write([]byte(t.String())); err != nil {
				requestChan <- time.Since(start)
				return
			}
		}
	})

	start := time.Now()
	resp, err := newHTTP3Client(t).Get(fmt.Sprintf("https://localhost:%d/shutdown", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = io.Copy(io.Discard, resp.Body)
	require.Error(t, err)
	var h3Err *http3.Error
	require.ErrorAs(t, err, &h3Err)
	require.Equal(t, http3.ErrCodeNoError, h3Err.ErrorCode)
	took := time.Since(start)
	require.InDelta(t, delay.Seconds(), took.Seconds(), (delay / 2).Seconds())

	// make sure that shutdown returned due to context deadline
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not return due to context deadline")
	}

	select {
	case requestDuration := <-requestChan:
		require.InDelta(t, delay.Seconds(), requestDuration.Seconds(), (delay / 2).Seconds())
	case <-time.After(time.Second):
		t.Fatal("did not receive request duration")
	}
}

func TestGracefulShutdownPendingStreams(t *testing.T) {
	rtt := scaleDuration(25 * time.Millisecond)

	handlerChan := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/helloworld", func(w http.ResponseWriter, r *http.Request) {
		handlerChan <- struct{}{}
		time.Sleep(rtt)
		w.Write([]byte("hello world"))
	})
	var server *http3.Server
	port := startHTTPServer(t, mux, func(s *http3.Server) { server = s })
	client := newHTTP3Client(t)

	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		DelayPacket: func(_ quicproxy.Direction, _, _ net.Addr, data []byte) time.Duration {
			return rtt
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	proxyPort := proxy.LocalAddr().(*net.UDPAddr).Port

	errChan := make(chan error, 1)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/helloworld", proxyPort), nil)
	require.NoError(t, err)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			errChan <- err
			return
		}
		if resp.StatusCode != http.StatusOK {
			errChan <- fmt.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
		}
	}()

	select {
	case <-handlerChan:
	case <-time.After(time.Second):
		t.Fatal("did not receive request")
	}

	shutdownChan := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { shutdownChan <- server.Shutdown(ctx) }()
	time.Sleep(rtt / 2) // wait for the server to start shutting down

	// make sure that the server rejects further requests
	for range 3 {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/helloworld", proxyPort), nil)
		require.NoError(t, err)
		_, err = client.Do(req)
		var h3err *http3.Error
		require.ErrorAs(t, err, &h3err)
		require.Equal(t, http3.ErrCodeRequestRejected, h3err.ErrorCode)
	}

	cancel()
	select {
	case err := <-shutdownChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not complete")
	}
}
