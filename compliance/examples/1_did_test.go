/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package examples

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/did"
	"os"
	"testing"
)

func TestNewDID(t *testing.T) {
	// for demonstration purpose we use a new generated RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 256)
	if err != nil {
		t.Fatal(err)
	}

	// build a JWK from the key, for the specification see https://www.rfc-editor.org/rfc/rfc7517

	// load a JWK from the private key, attention you SHOULD never publish this JWK since it contains "d" which is your private key
	JWK, err := jwk.FromRaw(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// retrieve a public key from the private key JWK
	JWKPublic, err := JWK.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	// export the JWK to a map so it can be convenient be added to the new DID
	JWKPublicAsMap, err := JWKPublic.AsMap(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a
	// resource for an X.509 public key certificate or certificate chain (see https://www.rfc-editor.org/rfc/rfc7517#section-4.6)
	JWKPublicAsMap["x5u"] = "http://url.to.your.certificate.chain"

	// The "alg" (algorithm) parameter identifies the algorithm intended for
	// use with the key.  The values used should either be registered in the
	// IANA "JSON Web Signature and Encryption Algorithms" registry
	// established by [JWA] or be a value that contains a Collision-
	// Resistant Name. (See https://www.rfc-editor.org/rfc/rfc7517#section-4.4)
	JWKPublicAsMap["alg"] = jwa.PS256

	// generate a new did with ID, since we want a did:web (see https://w3c-ccg.github.io/did-method-web/)
	// we use a did:web prefix followed by the domain e.g. did:web:gaia-x.eu
	DID := did.NewDID("did:web:test.test")

	// to add the public keys to the did we have to define Verification Methods, these are available for generic purpose
	// for specific methods like Assertion please see the specification
	DID.VerificationMethod = []did.VerificationMethod{
		{
			// Id a unique reference to the verification method usually retrieved from the did web uri with a added fragment
			Id: "did:web:test.test#RSA",
			// Controller usually equals the did id, for other usages see the DID spec
			Controller: "did:web:test.test",
			// There are two allowed methods publicKeyJWK and publicKeyMultibase where the later is not final yet, therefore
			// the use auf JsonWebKey is recommended
			Type: "JsonWebKey2020",
			// just insert the before build JWK MUST be the one with the public key
			PublicKeyJwk: JWKPublicAsMap,
		},
	}

	// since we want to use the verification method also explicitly for assertion we just add the key the list of
	// possible assertions methods
	DID.AssertionMethod = did.VerificationMethods{
		did.VerificationMethod{
			Id: "did:web:test.test#RSA",
		},
	}

	// render it to json to copy it to a did.json which then should be published according to the did web specification
	DIDPublicJson, err := json.MarshalIndent(DID, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(DIDPublicJson))
}

func TestNewDIDFromCertificate(t *testing.T) {
	// path to the certificate pem file which includes the private key
	path := os.Getenv("TestSignPrivateKeyFile")
	if path == "" {
		t.Fatal("missing env variable")
	}

	// read the certificate and parse it direct to a jwk set (attention jwk will be based on your private key!!)
	JWKSet, err := jwk.ReadFile(path, jwk.WithPEM(true))
	if err != nil {
		t.Fatal(err)
	}

	//in case the file contains multiple keys select the one you want to use
	privateKeyJWK, ok := JWKSet.Key(0)
	if !ok {
		t.Fatal("no key in set")
	}
	// from here you can follow the same approach as in the TestNewDID defined
	publicKeyJWK, err := privateKeyJWK.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	JWKPublicAsMap, err := publicKeyJWK.AsMap(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	JWKPublicAsMap["x5u"] = "http://url.to.your.certificate.chain"
	JWKPublicAsMap["alg"] = jwa.PS256

	DID := did.NewDID("did:web:test.test")

	DID.VerificationMethod = []did.VerificationMethod{
		{
			Id:           "did:web:test.test#RSA",
			Controller:   "did:web:test.test",
			Type:         "JsonWebKey2020",
			PublicKeyJwk: JWKPublicAsMap,
		},
	}

	DID.AssertionMethod = did.VerificationMethods{
		did.VerificationMethod{
			Id: "did:web:test.test#RSA",
		},
	}

	DIDPublicJson, err := json.MarshalIndent(DID, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(DIDPublicJson))

}
