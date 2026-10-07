package signaling

import (
	"context"
	"net"
	"testing"
	"time"
)

type fakeVerifier map[string]string

func (f fakeVerifier) VerifyDevice(ctx context.Context, token string) (string, error) {
	return f[token], nil
}

func TestSignalRegisterOfferAcceptTCPOnly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewServer(fakeVerifier{"token-a": "111222333", "token-b": "444555666"})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go s.ServeTCP(ctx, ln)

	a, err := Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	rctx, c := context.WithTimeout(ctx, 2*time.Second)
	defer c()
	ra, err := a.Register(rctx, "token-a")
	if err != nil {
		t.Fatal(err)
	}
	rb, err := b.Register(rctx, "token-b")
	if err != nil {
		t.Fatal(err)
	}
	if ra.Device != "111222333" || rb.Device != "444555666" {
		t.Fatal("wrong device mapping")
	}
	if ra.Cookie != "" || rb.Cookie != "" {
		t.Fatal("TCP-only registration should not issue UDP discovery cookies")
	}

	if err := a.Send(Message{Type: TypeConnect, Target: "444 555 666", SessionID: "session-1"}); err != nil {
		t.Fatal(err)
	}
	offer, err := b.Receive(rctx)
	if err != nil {
		t.Fatal(err)
	}
	if offer.Type != TypeOffer || offer.Device != "111222333" || len(offer.RelayToken) != 64 {
		t.Fatalf("bad offer: %+v", offer)
	}
	if len(offer.Candidates) != 0 {
		t.Fatalf("TCP-only offer advertised candidates: %+v", offer.Candidates)
	}

	if err := b.Send(Message{Type: TypeAccept, Target: offer.Device, SessionID: offer.SessionID, RelayToken: offer.RelayToken}); err != nil {
		t.Fatal(err)
	}
	accepted, err := a.Receive(rctx)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Type != TypeAccepted || accepted.Device != "444555666" || accepted.RelayToken != offer.RelayToken {
		t.Fatalf("bad accepted: %+v", accepted)
	}
	if len(accepted.Candidates) != 0 {
		t.Fatalf("TCP-only accept advertised candidates: %+v", accepted.Candidates)
	}
}
