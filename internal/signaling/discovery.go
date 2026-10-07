package signaling

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type DiscoveryRequest struct {
	Type   string `json:"type"`
	Cookie string `json:"cookie"`
}

type DiscoveryResponse struct {
	Type    string `json:"type"`
	Device  string `json:"device"`
	Address string `json:"address"`
}

func (s *Server) ServeDiscovery(ctx context.Context, pc net.PacketConn) error {
	defer pc.Close()
	buf := make([]byte, 2048)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					continue
				}
			}
			continue
		}
		var req DiscoveryRequest
		if json.Unmarshal(buf[:n], &req) != nil || req.Type != "discover" || req.Cookie == "" {
			continue
		}
		device, ok := s.DeviceForCookie(req.Cookie)
		if !ok {
			continue
		}
		resp, _ := json.Marshal(DiscoveryResponse{Type: "discovered", Device: device, Address: addr.String()})
		_, _ = pc.WriteTo(resp, addr)
	}
}

// ResolveDiscoveryUDP4 resolves the discovery endpoint explicitly as IPv4.
// The current NAT traversal socket is IPv4, so allowing generic udp resolution
// can make dual-stack DNS choose an IPv6 destination that this socket cannot use.
func ResolveDiscoveryUDP4(ctx context.Context, serverAddr string) (*net.UDPAddr, error) {
	host, portText, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("signal: invalid discovery address %q: %w", serverAddr, err)
	}
	port, err := net.LookupPort("udp", portText)
	if err != nil {
		return nil, fmt.Errorf("signal: invalid discovery port %q: %w", portText, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("signal: discovery endpoint %q is not IPv4", host)
		}
		return &net.UDPAddr{IP: ip4, Port: port}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("signal: resolve discovery host %q: %w", host, err)
	}
	for _, ip := range ips {
		if ip4 := net.IP(ip.AsSlice()).To4(); ip4 != nil {
			return &net.UDPAddr{IP: ip4, Port: port}, nil
		}
	}
	return nil, fmt.Errorf("signal: discovery host %q has no IPv4 address", host)
}

func Discover(ctx context.Context, conn *net.UDPConn, serverAddr, cookie string) (string, error) {
	addr, err := ResolveDiscoveryUDP4(ctx, serverAddr)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(DiscoveryRequest{Type: "discover", Cookie: cookie})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := conn.WriteToUDP(b, addr); err != nil {
			return "", fmt.Errorf("signal: send UDP discovery to %s from %s: %w", addr, conn.LocalAddr(), err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
		buf := make([]byte, 2048)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return "", fmt.Errorf("signal: read UDP discovery response: %w", err)
		}
		if !from.IP.Equal(addr.IP) {
			continue
		}
		var resp DiscoveryResponse
		if json.Unmarshal(buf[:n], &resp) == nil && resp.Type == "discovered" && resp.Address != "" {
			return resp.Address, nil
		}
	}
	return "", fmt.Errorf("signal: UDP discovery timed out (server=%s local=%s)", addr.String(), conn.LocalAddr().String())
}
