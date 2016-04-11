package clocklock

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/websocket"
	"net/http"
)

const (
	stateDisconnected = iota
	stateConnected
)

var (
	ErrClientDisconnected = errors.New("clocklock: Client disconnected")
)

type Client struct {
	conn   *websocket.Conn
	resp   *http.Response
	policy *Policy
	state  int
}

func NewClient(p *Policy) *Client {
	c := new(Client)
	c.policy = p
	c.state = stateDisconnected

	return c
}

func (c *Client) Connect() error {
	clockDialer := websocket.Dialer{
		Subprotocols:    []string{"json"},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	var err error
	c.conn, c.resp, err = clockDialer.Dial(c.policy.Url, nil)
	if err != nil {
		return err
	}

	c.state = stateConnected
	return nil
}

// Send request and receive response synchronistically
func (c *Client) SendReceive(req *Request) (*Response, error) {
	if c.state != stateConnected {
		return nil, ErrClientDisconnected
	}
	if req.Policy != c.policy.Id {
		return nil, ErrInvalidPolicyId
	}

	p, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	if err = c.conn.WriteMessage(websocket.TextMessage, p); err != nil {
		return nil, err
	}

	_, data, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	resp := new(Response)
	err = json.Unmarshal(data, resp)
	if err != nil {
		return resp, err
	}

	if !resp.Success {
		return resp, resp.Error
	}

	return resp, nil
}