/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package loire

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Posedio/gaia-x-go/did"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// TestExtendDIDFromCertificate resolves an already published did:web document
// and appends a new verification method (also referenced from assertionMethod)
// backed by an additional private key / certificate chain.
func TestExtendDIDFromCertificate(t *testing.T) {
	// resolve the existing did:web document we want to extend
	existingDID := "did:web:did.dumss.me"
	DID, err := did.ResolveDIDWeb(existingDID)
	if err != nil {
		t.Fatal(err)
	}

	// load the new private key from a PEM file
	set, err := jwk.ReadFile("../../key.pem", jwk.WithPEM(true))
	if err != nil {
		t.Fatal(err)
	}

	privateKeyJWK, ok := set.Key(0)
	if !ok {
		t.Fatal("no key in set")
	}

	// build the full certificate chain (leaf -> intermediates -> root) from cert.pem
	chainPEM, leafCert, err := buildFullCertChain("../../cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("chain5.pem", chainPEM, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote full chain (%d bytes) to chain5.pem; leaf expires %s", len(chainPEM), leafCert.NotAfter.UTC().Format(time.RFC3339))

	// derive the public JWK and decorate it with x5u + alg
	publicKeyJWK, err := privateKeyJWK.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	err = publicKeyJWK.Set("x5u", "https://did.dumss.me/.well-known/chain5.pem")
	if err != nil {
		t.Fatal(err)
	}
	err = publicKeyJWK.Set("alg", jwa.PS256())
	if err != nil {
		t.Fatal(err)
	}

	// id of the new verification method, scoped under the existing DID via fragment
	newVMID := existingDID + "#v2-2026"

	// append the new verification method to the existing DID; carry the leaf
	// cert's NotAfter as the verification method's expires (xsd:dateTime / RFC3339)
	DID.VerificationMethod = append(DID.VerificationMethod, did.VerificationMethod{
		Id:           newVMID,
		Controller:   existingDID,
		Type:         "JsonWebKey2020",
		PublicKeyJwk: publicKeyJWK,
		Expires:      leafCert.NotAfter.UTC().Format(time.RFC3339),
	})

	// also list it as an assertion method (by reference)
	DID.AssertionMethod = append(DID.AssertionMethod, did.VerificationMethod{
		Id: newVMID,
	})

	DIDPublicJson, err := json.MarshalIndent(DID, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	err = DID.ResolveMethods()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(DIDPublicJson))
}

// buildFullCertChain reads a leaf certificate from a PEM file and walks the
// AIA "CA Issuers" extension upward, fetching each issuer until it reaches a
// self-signed root. It returns the PEM bundle ordered leaf -> ... -> root and
// the parsed leaf certificate (so callers can use NotAfter, etc.).
func buildFullCertChain(leafPath string) ([]byte, *x509.Certificate, error) {
	leafPEM, err := os.ReadFile(leafPath)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block found in %s", leafPath)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	chain := []*x509.Certificate{leaf}
	current := leaf
	for !isSelfSigned(current) {
		if len(current.IssuingCertificateURL) == 0 {
			return nil, nil, fmt.Errorf("certificate %q has no AIA CA Issuers URL; cannot continue chain", current.Subject)
		}
		issuer, err := fetchIssuerCert(current.IssuingCertificateURL[0])
		if err != nil {
			return nil, nil, fmt.Errorf("fetch issuer for %q: %w", current.Subject, err)
		}
		chain = append(chain, issuer)
		current = issuer
	}

	var out bytes.Buffer
	for _, c := range chain {
		if err := pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return nil, nil, err
		}
	}
	return out.Bytes(), leaf, nil
}

// isSelfSigned reports whether the certificate's signature verifies against
// its own public key — the standard test for a root.
func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(c) == nil
}

// fetchIssuerCert downloads a certificate from a CA Issuers URL. Per RFC 5280
// the resource may be DER or PEM (or PKCS#7); we handle DER and PEM here,
// which covers every public CA the chain is likely to traverse.
func fetchIssuerCert(url string) (*x509.Certificate, error) {
	c := http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s from %s", resp.Status, url)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if cert, err := x509.ParseCertificate(body); err == nil {
		return cert, nil
	}
	if block, _ := pem.Decode(body); block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, errors.New("issuer response is neither DER nor PEM certificate")
}
