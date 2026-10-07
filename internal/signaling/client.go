package signaling

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Client struct {
	conn net.Conn
	enc  *json.Encoder
	dec  *json.Decoder
	mu   sync.Mutex
}

func Dial(ctx context.Context, address string) (*Client, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, errors.New("signal: address is empty")
	}
	useTLS := false
	serverName := ""
	switch {
	case strings.HasPrefix(address, "tls://"):
		useTLS = true
		address = strings.TrimPrefix(address, "tls://")
	case strings.HasPrefix(address, "tcp://"):
		address = strings.TrimPrefix(address, "tcp://")
	}
	if host, _, err := net.SplitHostPort(address); err == nil {
		serverName = host
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.DialWithDialer(&d, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName})
	} else {
		conn, err = d.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, fmt.Errorf("signal: dial %s: %w", address, err)
	}
	return &Client{conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(conn)}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) Send(m Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enc.Encode(m)
}

func (c *Client) Receive(ctx context.Context) (Message, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetReadDeadline(deadline)
	} else {
		_ = c.conn.SetReadDeadline(time.Time{})
	}
	var m Message
	if err := c.dec.Decode(&m); err != nil {
		return m, err
	}
	if m.Type == TypeError {
		if m.Error == "" {
			m.Error = "signalling server error"
		}
		return m, errors.New(m.Error)
	}
	return m, nil
}

func (c *Client) Register(ctx context.Context, token string) (Message, error) {
	if token == "" {
		return Message{}, errors.New("signal: empty device token")
	}
	if err := c.Send(Message{Type: TypeRegister, Token: token}); err != nil {
		return Message{}, err
	}
	m, err := c.Receive(ctx)
	if err != nil {
		return Message{}, err
	}
	if m.Type != TypeRegistered || m.Device == "" {
		return Message{}, fmt.Errorf("signal: invalid register response: %s", m.Type)
	}
	return m, nil
}
