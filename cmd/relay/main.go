package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type waitingConn struct {
	conn    net.Conn
	created time.Time
}

func main() {
	addr := flag.String("addr", ":46000", "relay TCP/TLS listen address")
	certPath := flag.String("cert", os.Getenv("REMOTE_TLS_CERT"), "TLS certificate PEM")
	keyPath := flag.String("key", os.Getenv("REMOTE_TLS_KEY"), "TLS private key PEM")
	waitTTL := flag.Duration("wait-ttl", 30*time.Second, "maximum time to wait for the second peer")
	flag.Parse()

	if (*certPath == "") != (*keyPath == "") {
		fmt.Fprintln(os.Stderr, "both TLS certificate and private key must be configured")
		os.Exit(2)
	}

	ln, err := listen(*addr, *certPath, *keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "relay listen error:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	transport := "TCP"
	if *certPath != "" {
		transport = "TLS"
	}
	fmt.Printf("payload-blind relay listening on %s over %s\n", *addr, transport)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var mu sync.Mutex
	waiting := make(map[string]waitingConn)

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				mu.Lock()
				for token, item := range waiting {
					_ = item.conn.Close()
					delete(waiting, token)
				}
				mu.Unlock()
				return
			case now := <-ticker.C:
				mu.Lock()
				for token, item := range waiting {
					if now.Sub(item.created) > *waitTTL {
						_ = item.conn.Close()
						delete(waiting, token)
					}
				}
				mu.Unlock()
			}
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintln(os.Stderr, "relay accept error:", err)
			continue
		}
		go handleConnection(conn, &mu, waiting)
	}
}

func listen(addr, certPath, keyPath string) (net.Listener, error) {
	if certPath == "" {
		return net.Listen("tcp", addr)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}

	return tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
}

func handleConnection(conn net.Conn, mu *sync.Mutex, waiting map[string]waitingConn) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	tokenBytes := make([]byte, 64)
	if _, err := io.ReadFull(conn, tokenBytes); err != nil {
		_ = conn.Close()
		return
	}

	token := string(tokenBytes)
	if _, err := hex.DecodeString(token); err != nil {
		_ = conn.Close()
		return
	}

	_ = conn.SetReadDeadline(time.Time{})

	mu.Lock()
	first, exists := waiting[token]
	if exists {
		delete(waiting, token)
		mu.Unlock()
		fmt.Println("relay peer pair established")
		go pipe(first.conn, conn)
		return
	}

	waiting[token] = waitingConn{conn: conn, created: time.Now()}
	mu.Unlock()
}

func pipe(a, b net.Conn) {
	defer a.Close()
	defer b.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
	}()

	wg.Wait()
}
