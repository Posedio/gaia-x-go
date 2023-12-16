/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package compliance

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"os"
	"testing"
)

func TestTCSigned(t *testing.T) {
	path := os.Getenv("TestSignPrivateKeyFile")
	if path == "" {
		t.Fatal("missing env variable")
	}

	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("error while reading conf: %v", err)
	}

	block, _ := pem.Decode(file)
	priKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	pk, ok := priKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("error on rsa key parse")
	}

	raw, err := jwk.FromRaw(pk)
	if err != nil {
		t.Fatal(err)
	}

	c, err := NewComplianceConnector(signUrlB, ArubaV1Notary, "22.10", raw, "did:web:vc.mivp.group", "did:web:vc.mivp.group#X509-JWK2020")
	if err != nil {
		t.Fatal(err)
	}

	tc, err := c.SignTermsAndConditions("https://test.test.test")
	if err != nil {
		t.Fatal(err)
	}
	json, err := tc.ToJson()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(json))

	t.Log(tc.Proof.Proofs[0].JWS)

	err = tc.Verify()
	if err != nil {
		t.Fatal(err)
	}

}
func TestTCSignedCompliance2210(t *testing.T) {
	path := os.Getenv("TestSignPrivateKeyFile")
	if path == "" {
		t.Fatal("missing env variable")
	}

	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("error while reading conf: %v", err)
	}

	block, _ := pem.Decode(file)
	priKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	pk, ok := priKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("error on rsa key parse")
	}

	raw, err := jwk.FromRaw(pk)
	if err != nil {
		t.Fatal(err)
	}

	c, err := NewComplianceConnector(signUrlB, ArubaV1Notary, "22.10", raw, "did:web:vc.mivp.group", "did:web:vc.mivp.group#X509-JWK2020")
	if err != nil {
		t.Fatal(err)
	}

	tc, err := c.SignTermsAndConditions("https://test.test.test")
	if err != nil {
		t.Fatal(err)
	}
	json, err := tc.ToJson()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(json))

	t.Log([]byte(tc.Proof.Proofs[0].JWS))
	t.Log(tc.Proof.Proofs[0].JWS)

	err = tc.Verify()
	if err != nil {
		t.Fatal(err)
	}

}
