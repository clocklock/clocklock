package clocklock

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"
	"time"
)

func TestJSON(t *testing.T) {
	// Unmarshal the rule
	data, err := ioutil.ReadFile("./test/boulder-unordered-256.json")
	if err != nil {
		t.Error(err)
	}
	rule := new(Rule)
	json.Unmarshal(data, rule)

	// Round-trip the rule through JSON and make sure it's the same
	data2, err := json.Marshal(rule)
	if err != nil {
		t.Error(err)
	}
	rule2 := new(Rule)
	json.Unmarshal(data2, rule2)
	if !reflect.DeepEqual(rule, rule2) {
		t.Error("Rule does not survive round-trip")
	}
}

func TestRequestResponse(t *testing.T) {
	// Create the request
	digest, err := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if err != nil {
		t.Error(err)
	}
	req := NewRequest("boulder-ordered-256", crypto.SHA256, digest)
	req.GenerateNonce()

	// Unmarshal the rule
	data, err := ioutil.ReadFile("./test/boulder-unordered-256.json")
	if err != nil {
		t.Error(err)
	}
	rule := new(Rule)
	json.Unmarshal(data, rule)

	// Unpack the certificate
	certID := "718bb32b15a83ea12526b807d6e717d2544585f60c20acfc44dd13233eaca8cf"
	cert, err := rule.GetCert(certID)
	if err != nil {
		t.Error(err)
	}

	// Add the test certificate to the trusted list
	RootCerts = x509.NewCertPool()
	RootCerts.AddCert(cert)

	// Get the private key for signing
	pem, err := ioutil.ReadFile("./test/boulder-ordered-256.ec-p256.pem")
	if err != nil {
		t.Error(err)
	}
	privcert, err := tls.X509KeyPair([]byte(rule.Certs[certID]), pem)
	if err != nil {
		t.Error(err)
	}
	priv := privcert.PrivateKey.(*ecdsa.PrivateKey)

	// Create the response
	resp := Response{Success: true, Serial: 123, Time: time.Now(), Accuracy: 12345678, Request: *req}

	// Add the Certificate ID
	resp.Cert = certID

	// Sign the response
	sig, err := priv.Sign(rand.Reader, resp.TimeStampToken(), req.Hash)
	if err != nil {
		t.Error(err)
	}

	// Add the signature to the response
	resp.Signature = sig

	// Verify the response
	err = resp.Verify(req, cert)
	if err != nil {
		t.Error(err)
	}
}
