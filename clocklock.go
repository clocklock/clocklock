package clocklock

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/phayes/cryptoid"
	"math/big"
	"strconv"
	"time"
)

var (
	ErrInvalidPEMBlock       = errors.New("Invalid PEM Block.")
	ErrInvalidCertificatePEM = errors.New("Invalid Certificate")
	ErrInvalidPublicPEM      = errors.New("Invalid Public Key")
	ErrInvalidPolicyId       = errors.New("Invaid Policy ID.")
	ErrInvalidCertificateId  = errors.New("Invaid Certificate / Public Key ID.")
	ErrInvalidNonce          = errors.New("Invalid Nonce")
	ErrInvalidSignature      = errors.New("Invalid Signature")
	ErrMismatchedHash        = errors.New("Mismatched Hash Digest")
)

type Request struct {
	Policy string      `json:"policy"` // Policy ID
	Hash   crypto.Hash `json:"hash"`   // numeric ID of the hash algorithm for the digest. Will be a string-name in JSON.
	Digest []byte      `json:"digest"` // When converting and from to json, should be in hex format
	Nonce  uint64      `json:"nonce"`  // 8 bytes of random data represented numerically as an uint64. Assumed to be 0 if elided.
	Cert   string      `json:"cert"`   // Cert ID to request for signing. Optional. Hex encoding of the SHA256 fingerprint of the DER certificate.
}

func (req *Request) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		*Request
		Hash string
	}{
		Request: req,
		Hash:    cryptoid.HashAlgorithmByCrypto(req.Hash).Name,
	})
}

func (req *Request) UnmarshalJSON(data []byte) error {
	un := struct {
		*Request
		Hash string
	}{
		Request: req,
	}

	err := json.Unmarshal(data, &un)
	if err != nil {
		return err
	}
	hashAlgo, err := cryptoid.HashAlgorithmByName(un.Hash)
	if err != nil {
		return err
	}
	if hashAlgo.Hash == 0 {
		return cryptoid.UnableToFind
	}

	// Set values
	req.Policy = un.Policy
	req.Hash = hashAlgo.Hash
	req.Digest = un.Digest
	req.Nonce = un.Nonce
	req.Cert = un.Cert

	return nil
}

type Response struct {
	Success   bool          `json:"success"`
	Serial    uint64        `json:"serial"`
	Time      time.Time     `json:"time"`      // Nanosecond precision ISO 8601 timestamp. Must be UTC zoned.
	Accuracy  time.Duration `json:"accuracy"`  // Accuracy in nano seconds. 0 means Perfect Accuracy (see doc). Must be provided.
	Signature []byte        `json:"signature"` // When converting to json, should be in hex format
	Request
	Error *ResponseError `json:"error"`
}

// The TimeStampToken is the sha256 hash of the concactenation of the following:
// - Hash ID
// - digest bytes
// - time
// - accuracy
// - serial
// - policyID
// - nonce.
// Time is measured as the number of nanoseconds since 1970-01-01T00:00:00 UTC. Note that we include leapseconds,
// so this will be 26 seconds (26,000,000,000 ns) ahead of the equivilent POSIX timestamp.
// The numeric portions (hash-id, time, accuracy, serial) are in 64 bit big edian format.
// Even if the nonce is elided, it is still inclulded as a zeoroed out 8 bytes.
func (resp *Response) TimeStampToken() []byte {
	b := make([]byte, 8, 8)

	buf := sha256.New()

	// Hash ID
	binary.BigEndian.PutUint64(b, uint64(resp.Hash))
	buf.Write(b)

	// Digest bytes
	buf.Write(resp.Digest)

	// Time
	nano := resp.Time.UnixNano() + (26000000000) // Add 26 seconds to account for leapseconds
	binary.BigEndian.PutUint64(b, uint64(nano))
	buf.Write(b)

	// Accuracy
	binary.BigEndian.PutUint64(b, uint64(resp.Accuracy))
	buf.Write(b)

	// Serial Number
	binary.BigEndian.PutUint64(b, resp.Serial)
	buf.Write(b)

	// Policy id
	buf.Write([]byte(resp.Policy))

	// Nonce
	binary.BigEndian.PutUint64(b, resp.Nonce)
	buf.Write(b)

	return buf.Sum(nil)
}

// Fully verify the response
// The caller is responsible for passing the correct certificate (as retreived from the policy)
func (resp *Response) Verify(req *Request, cert *x509.Certificate) error {
	if !resp.Success {
		return resp.Error
	}

	if resp.Nonce != req.Nonce {
		return ErrInvalidNonce
	}

	if resp.Hash != req.Hash {
		return ErrMismatchedHash
	}

	// If a particular cert was requested, check to make sure the same one is noted in the response
	if req.Cert != "" {
		if resp.Cert != req.Cert {
			return ErrInvalidCertificateId
		}
	}

	// Verify the certificate ID matches the certificate passed in
	rawCertId := sha256.Sum256(cert.Raw)
	if hex.Dump(rawCertId[:]) != resp.Cert {
		return ErrInvalidCertificateId
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	// Verify that the certificate signs the hashstamp and the certificate ID is correct
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(pub, resp.Hash, resp.TimeStampToken(), resp.Signature)
		if err != nil {
			return ErrInvalidSignature
		}
	case *ecdsa.PublicKey:
		// First extract r and s from the DER (as per RFC 3278 Sec 8.2)
		sig := struct {
			R *big.Int
			S *big.Int
		}{}
		_, err := asn1.Unmarshal(resp.Signature, &sig)
		if err != nil {
			return ErrInvalidPublicPEM
		}
		// Check the signature
		if !ecdsa.Verify(pub, resp.TimeStampToken(), sig.R, sig.S) {
			return ErrInvalidSignature
		}
	default:
		return ErrInvalidPublicPEM
	}

	return nil
}

type Policy struct {
	Id             string            `json:"id"`
	Oid            string            `json:"oid,omitempty"`   // Optional. ASN1 OID if available.
	Url            string            `json:"url"`             // The URL to connect for the policy. Generally the same URL where there policy was gotten in the first place.
	Name           string            `json:"name"`            // Human readable name
	Description    string            `json:"desc"`            // Human readable description
	Active         bool              `json:"active"`          // Is the policy actively available for use?
	Ordered        bool              `json:"ordered"`         // Do the serial numbers provided increase monotonically with time
	Supports       []string          `json:"supports"`        // List of hash identifiers that this policy supports
	StampTimeout   time.Duration     `json:"stamp-timeout"`   // Maximum time in nanoseconds between receiving a request and stamping it.
	RequestTimeout time.Duration     `json:"request-timeout"` // Maximum time in nanoseconds between receiving a request and returning a response.
	Accuracy       time.Duration     `json:"accuracy"`        // Maximum Accuracy in nanoseconds. Any response that would result in an accuracy over this maximum will instead return an error. A value of 0 implies Perfect Accuracy.
	Log            string            `json:"log"`             // Can be one of 'none', 'serial', 'hash'. Specifies how much information is stored in the TSA and available for query. Note that 'serial' and 'hash' have performance implications
	Certs          map[string]string `json:"certs"`           // Certificates in PEM format.
	Public         map[string]string `json:"public"`          // List of currently active signing public key in base64 format. Generally only one, but if a revocation or expiry is pending, then there may be more than one during the switchover.
	Preferred      string            `json:"preferred"`       // Preferred Certificate. Will use this one if no cert is specified.
	RFC3161        bool              `json:"rfc3161"`         // Does this policy support RFC 3161
	Info           interface{}       `json:"info,omitempty"`  // Any additional TSA specific information
}

func (policy *Policy) GetCert(certId string) (*x509.Certificate, error) {
	certPEM, ok := policy.Certs[certId]
	if !ok {
		return nil, ErrInvalidCertificateId
	}

	// Parse the certificate
	certPEMBlock, _ := pem.Decode([]byte(certPEM))
	if certPEMBlock == nil {
		return nil, ErrInvalidPEMBlock
	}
	if certPEMBlock.Type != "CERTIFICATE" {
		return nil, ErrInvalidCertificatePEM
	}
	cert, err := x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (policy *Policy) GetCerts() ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	if policy.Certs == nil {
		return certs, nil
	}

	for certId, _ := range policy.Certs {
		cert, err := policy.GetCert(certId)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func (policy *Policy) GetPublicKey(certId string) (interface{}, error) {
	keyPEM, ok := policy.Public[certId]
	if !ok {
		return nil, ErrInvalidCertificateId
	}

	keyPEMBlock, _ := pem.Decode([]byte(keyPEM))
	if keyPEMBlock == nil {
		return nil, ErrInvalidPublicPEM
	}
	if keyPEMBlock.Type != "RSA PUBLIC KEY" && keyPEMBlock.Type != "EC PUBLIC KEY" && keyPEMBlock.Type != "PUBLIC KEY" {
		return nil, ErrInvalidPublicPEM
	}

	pub, err := x509.ParsePKIXPublicKey(keyPEMBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return pub, nil
}

// Get all public keys.
// Each interface{} item will be one of
func (policy *Policy) GetPublicKeys() ([]interface{}, error) {
	pubs := []interface{}{}

	if policy.Public == nil {
		return pubs, nil
	}

	for certId, _ := range policy.Public {
		pub, err := policy.GetPublicKey(certId)
		if err != nil {
			return nil, err
		}
		pubs = append(pubs, pub)
	}

	return pubs, nil
}

func (policy *Policy) SupportedHashes() ([]crypto.Hash, error) {
	supported := []crypto.Hash{}

	for _, name := range policy.Supports {
		hashIdentifier, err := cryptoid.HashAlgorithmByName(name)
		if err != nil {
			return nil, err
		}
		supported = append(supported, hashIdentifier.Hash)
	}

	return supported, nil
}

type PolicyList map[string]Policy

type ResponseError struct {
	*ErrorCode
	Message error `json:message` // Any additional information about this error
}

func NewResponseError(code *ErrorCode, err error) *ResponseError {
	return &ResponseError{ErrorCode: code, Message: err}
}

func (err *ResponseError) Error() string {
	if err.Message != nil {
		return err.ErrorCode.Error() + ". " + err.Message.Error()
	} else {
		return err.ErrorCode.Error()
	}
}

type ErrorCode struct {
	Code int    `json:code`
	Err  string `json:error`
}

func (err *ErrorCode) Error() string {
	return "Error " + strconv.Itoa(err.Code) + ": " + err.Err
}

var (
	ErrorCodeUnknownError    = &ErrorCode{0, "Unknown Error"}
	ErrorCodeInvalidRequest  = &ErrorCode{1, "Invalid Request"}
	ErrorCodeServerError     = &ErrorCode{2, "Server Error"}
	ErrorCodeUnsupportedHash = &ErrorCode{3, "Unsupported Hash Algorithm"}
	ErrorCodeBadDigestLength = &ErrorCode{4, "Bad Digest Length for given Hash Algorithm"}
	ErrorCodeStampTimeout    = &ErrorCode{5, "Stamp Timeout"}
	ErrorCodeRequestTimeout  = &ErrorCode{6, "Request Timeout"}
	ErrorCodeAccuracy        = &ErrorCode{7, "Accuracy Error"}
	ErrorBadPolicy           = &ErrorCode{7, "Unacceptable Policy"}
	ErrorBadCert             = &ErrorCode{7, "Unacceptable Cert"}
	ErrorPolicyUpdated       = &ErrorCode{7, "Policy Updated"}
)
