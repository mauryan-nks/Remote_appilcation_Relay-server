package signaling

import "encoding/json"

type Candidate struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

type Message struct {
	Type       string          `json:"type"`
	Device     string          `json:"device,omitempty"`
	Target     string          `json:"target,omitempty"`
	Token      string          `json:"token,omitempty"`
	Cookie     string          `json:"cookie,omitempty"`
	SessionID  string          `json:"session_id,omitempty"`
	RelayToken string          `json:"relay_token,omitempty"`
	Candidates []Candidate     `json:"candidates,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Error      string          `json:"error,omitempty"`
}

const (
	TypeRegister   = "register"
	TypeRegistered = "registered"
	TypePing       = "ping"
	TypePong       = "pong"
	TypeConnect    = "connect"
	TypeOffer      = "offer"
	TypeAccept     = "accept"
	TypeAccepted   = "accepted"
	TypeReject     = "reject"
	TypeRejected   = "rejected"
	TypeError      = "error"
)
