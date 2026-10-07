package signaling

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type DeviceVerifier interface {
	VerifyDevice(ctx context.Context, token string) (deviceCode string, err error)
}

type HTTPVerifier struct {
	APIURL string
	HTTP   *http.Client
}

type meResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Device struct {
			DeviceCode string `json:"device_code"`
		} `json:"device"`
	} `json:"data"`
	Message string `json:"message"`
}

func (v *HTTPVerifier) VerifyDevice(ctx context.Context, token string) (string, error) {
	if strings.TrimSpace(v.APIURL) == "" {
		return "", errors.New("signal: CI4 API URL is not configured")
	}
	httpClient := v.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(v.APIURL, "/")+"/api/v1/device/me", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("signal: device token validation returned HTTP %d", resp.StatusCode)
	}
	var out meResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	code := digits(out.Data.Device.DeviceCode)
	if !out.Success || code == "" {
		return "", errors.New("signal: device token validation failed")
	}
	return code, nil
}

type Server struct {
	Verifier DeviceVerifier

	mu      sync.RWMutex
	clients map[string]*serverClient
}

type serverClient struct {
	device string
	conn   net.Conn
	enc    *json.Encoder
	mu     sync.Mutex
}

func NewServer(v DeviceVerifier) *Server {
	return &Server{Verifier: v, clients: map[string]*serverClient{}}
}

func (s *Server) ServeTCP(ctx context.Context, ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) ListenAndServe(ctx context.Context, addr, certFile, keyFile string) error {
	var ln net.Listener
	var err error
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return errors.New("signal: both -cert and -key are required")
		}
		cert, e := tls.LoadX509KeyPair(certFile, keyFile)
		if e != nil {
			return e
		}
		ln, err = tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	err = s.ServeTCP(ctx, ln)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	cl := &serverClient{conn: conn, enc: json.NewEncoder(conn)}
	defer func() {
		if cl.device != "" {
			s.mu.Lock()
			if s.clients[cl.device] == cl {
				delete(s.clients, cl.device)
			}
			s.mu.Unlock()
		}
	}()

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var first Message
	if err := dec.Decode(&first); err != nil {
		return
	}
	if first.Type != TypeRegister || first.Token == "" {
		_ = cl.send(Message{Type: TypeError, Error: "register with a device token first"})
		return
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	deviceCode, err := s.Verifier.VerifyDevice(verifyCtx, first.Token)
	cancel()
	if err != nil {
		_ = cl.send(Message{Type: TypeError, Error: err.Error()})
		return
	}
	cl.device = deviceCode
	s.mu.Lock()
	if old := s.clients[deviceCode]; old != nil && old != cl {
		_ = old.conn.Close()
	}
	s.clients[deviceCode] = cl
	s.mu.Unlock()
	if err := cl.send(Message{Type: TypeRegistered, Device: deviceCode}); err != nil {
		return
	}

	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		var m Message
		if err := dec.Decode(&m); err != nil {
			return
		}
		m.Device = deviceCode
		switch m.Type {
		case TypePing:
			_ = cl.send(Message{Type: TypePong, Device: deviceCode})
		case TypeConnect:
			target := digits(m.Target)
			if target == "" || m.SessionID == "" {
				_ = cl.send(Message{Type: TypeError, Error: "target and session_id are required"})
				continue
			}
			relayToken, e := randomHex(32)
			if e != nil {
				continue
			}
			m.Target = target
			m.RelayToken = relayToken
			if !s.forward(target, Message{Type: TypeOffer, Device: deviceCode, Target: target, SessionID: m.SessionID, RelayToken: relayToken, Candidates: m.Candidates}) {
				_ = cl.send(Message{Type: TypeRejected, Device: target, SessionID: m.SessionID, Error: "target device is offline"})
			}
		case TypeAccept:
			if m.Target == "" || m.SessionID == "" {
				continue
			}
			s.forward(digits(m.Target), Message{Type: TypeAccepted, Device: deviceCode, Target: digits(m.Target), SessionID: m.SessionID, RelayToken: m.RelayToken, Candidates: m.Candidates})
		case TypeReject:
			s.forward(digits(m.Target), Message{Type: TypeRejected, Device: deviceCode, Target: digits(m.Target), SessionID: m.SessionID, Error: m.Error})
		}
	}
}

func (s *Server) forward(device string, m Message) bool {
	s.mu.RLock()
	target := s.clients[device]
	s.mu.RUnlock()
	if target == nil {
		return false
	}
	return target.send(m) == nil
}

func (c *serverClient) send(m Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enc.Encode(m)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func digits(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// DeviceForCookie is retained only so older discovery.go source trees still
// compile when Phase 4.3 is applied as an overlay. TCP-only mode never issues
// or consumes UDP discovery cookies.
func (s *Server) DeviceForCookie(cookie string) (string, bool) {
	return "", false
}
