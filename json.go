package clocklock

import (
	"encoding/hex"
	"encoding/json"
	"github.com/phayes/cryptoid"
	"time"
)

func (req *Request) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Rule   string `json:"rule"`
		Hash   string `json:"hash"`
		Digest string `json:"digest"`
		Nonce  uint64 `json:"nonce,omitempty"`
		Cert   string `json:"cert,omitempty"`
	}{
		Rule:   req.Rule,
		Hash:   cryptoid.HashAlgorithmByCrypto(req.Hash).Name,
		Digest: hex.EncodeToString(req.Digest),
		Nonce:  req.Nonce,
		Cert:   req.Cert,
	})
}

func (req *Request) UnmarshalJSON(data []byte) error {
	un := new(struct {
		Rule   string `json:"rule"`
		Hash   string `json:"hash"`
		Digest string `json:"digest"`
		Nonce  uint64 `json:"nonce,omitempty"`
		Cert   string `json:"cert,omitempty"`
	})

	err := json.Unmarshal(data, un)
	if err != nil {
		return err
	}

	// Get hash algo
	hashAlgo, err := cryptoid.HashAlgorithmByName(un.Hash)
	if err != nil {
		return err
	}
	if hashAlgo.Hash == 0 {
		return cryptoid.UnableToFind
	}

	// Get the digest bytes
	digest, err := hex.DecodeString(un.Digest)
	if err != nil {
		return err
	}

	// Set values
	req.Rule = un.Rule
	req.Hash = hashAlgo.Hash
	req.Digest = digest
	req.Nonce = un.Nonce
	req.Cert = un.Cert

	return nil
}

func (resp *Response) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Success   bool           `json:"success"`
		Serial    uint64         `json:"serial"`
		Time      time.Time      `json:"time"`
		Accuracy  time.Duration  `json:"accuracy"`
		Signature []byte         `json:"signature"`
		Rule      string         `json:"rule"`
		Hash      string         `json:"hash"`
		Digest    string         `json:"digest"`
		Nonce     uint64         `json:"nonce,omitempty"`
		Cert      string         `json:"cert,omitempty"`
		Error     *ResponseError `json:"error"`
	}{
		Success:   resp.Success,
		Serial:    resp.Serial,
		Time:      resp.Time,
		Accuracy:  resp.Accuracy,
		Signature: resp.Signature,
		Rule:      resp.Rule,
		Hash:      cryptoid.HashAlgorithmByCrypto(resp.Hash).Name,
		Digest:    hex.EncodeToString(resp.Digest),
		Nonce:     resp.Nonce,
		Cert:      resp.Cert,
		Error:     resp.Error,
	})
}

func (resp *Response) UnmarshalJSON(data []byte) error {
	un := new(struct {
		Success   bool           `json:"success"`
		Serial    uint64         `json:"serial"`
		Time      time.Time      `json:"time"`
		Accuracy  time.Duration  `json:"accuracy"`
		Signature []byte         `json:"signature"`
		Error     *ResponseError `json:"error"`
	})

	err := json.Unmarshal(data, un)
	if err != nil {
		return err
	}

	// Unmarshal Request
	req := new(Request)
	err = json.Unmarshal(data, req)
	if err != nil {
		return err
	}

	// Set values
	resp.Success = un.Success
	resp.Serial = un.Serial
	resp.Time = un.Time
	resp.Accuracy = un.Accuracy
	resp.Signature = un.Signature
	resp.Request = *req
	resp.Error = un.Error

	return nil
}
