/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package compliance

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/verifiableCredentials"
)

var signUrlB = V1Staging

var exSD2210 = map[string]interface{}{
	"@context": []interface{}{
		"https://www.w3.org/2018/credentials/v1",
		trustFrameWorkURL,
	},
	"type": []interface{}{
		"VerifiableCredential",
	},
	"id":           "did:web:randomized.group",
	"issuanceDate": "2023-12-14T18:30:45.789Z",
	"issuer":       "did:web:randomized.group",
	"credentialSubject": map[string]interface{}{
		"id":           "did:web:randomized.euprogigant.io",
		"type":         "gx:LegalParticipant",
		"gx:name":      "Randomized Institute",
		"gx:legalName": "Random University",
		"gx:legalRegistrationNumber": map[string]interface{}{
			"gx:vatID":   "AT987654321",
			"gx:leiCode": "987654321987654321",
		},
		"gx:headquarterAddress": map[string]interface{}{
			"gx:addressCountryCode":     "AT",
			"gx:addressCode":            "AT-9",
			"gx:countrySubdivisionCode": "AT-9",
			"gx:streetAddress":          "Musterstraße 123",
			"gx:postalCode":             "12345",
			"gx:locality":               "Musterstadt",
		},
		"gx:legalAddress": map[string]interface{}{
			"gx:addressCountryCode":     "AT",
			"gx:addressCode":            "AT-9",
			"gx:countrySubdivisionCode": "AT-9",
			"gx:streetAddress":          "Hauptstraße 456",
			"gx:postalCode":             "54321",
			"gx:locality":               "Hauptstadt",
		},
		"gx-terms-and-conditions:gaiaxTermsAndConditions": "70c1d713215f95191a11d38fe2341faed27d19e083917bc8732ca4fea4976700",
	},
}

var exampleSD2210 = `
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#"
    ],
    "type": [
        "VerifiableCredential"
    ],
    "id": "did:web:randomized.group",
    "issuanceDate": "2023-12-14T18:30:45.789Z",
    "issuer": "did:web:randomized.group",
    "credentialSubject": {
        "id": "did:web:randomized.euprogigant.io",
        "type": "gx:LegalParticipant",
        "gx:name": "Randomized Institute",
        "gx:legalName": "Random University",
        "gx:legalRegistrationNumber": {
            "gx:vatID": "AT987654321",
            "gx:leiCode": "987654321987654321"
        },
        "gx:headquarterAddress": {
            "gx:addressCountryCode": "AT",
            "gx:addressCode": "AT-9",
            "gx:countrySubdivisionCode": "AT-9",
            "gx:streetAddress": "Musterstraße 123",
            "gx:postalCode": "12345",
            "gx:locality": "Musterstadt"
        },
        "gx:legalAddress": {
            "gx:addressCountryCode": "AT",
            "gx:addressCode": "AT-9",
            "gx:countrySubdivisionCode": "AT-9",
            "gx:streetAddress": "Hauptstraße 456",
            "gx:postalCode": "54321",
            "gx:locality": "Hauptstadt"
        },
        "gx-terms-and-conditions:gaiaxTermsAndConditions": "70c1d713215f95191a11d38fe2341faed27d19e083917bc8732ca4fea4976700"
    }
}
`

func TestNormalize(t *testing.T) {
	assertions := assert.New(t)

	proc := ld.NewJsonLdProcessor()

	options := ld.NewJsonLdOptions("")
	options.UseRdfType = true
	options.Format = "application/n-quads"
	options.Algorithm = ld.AlgorithmURDNA2015
	//options.ProduceGeneralizedRdf = true
	options.SafeMode = true
	options.OmitGraph = true

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 10
	retryClient.RetryWaitMax = 1 * time.Second
	retryClient.HTTPClient.Timeout = 2 * time.Second
	retryClient.CheckRetry = verifiableCredentials.DefaultRetryPolicy

	client := retryClient.StandardClient()

	loader := verifiableCredentials.NewDocumentLoader(client)

	options.DocumentLoader = loader

	n, err := proc.Normalize(exSD2210, options)
	if err != nil {
		t.Fatalf("jsongold error: %v", err)
	}

	t.Log(n)

	assertions.IsType("", n)

}

func TestSign(t *testing.T) {
	vc := &verifiableCredentials.VerifiableCredential{}
	err := json.Unmarshal([]byte(exampleSD2210), vc)
	if err != nil {
		t.Fatal(err)
	}

	n, err := vc.CanonizeGo()
	if err != nil {
		t.Fatal(err)
	}

	priKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := jwk.FromRaw(priKey)
	if err != nil {
		t.Fatal(err)
	}

	signed, _, err := generateJWS(n, raw)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(signed))
}

func TestSelfSigned(t *testing.T) {
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

	c, err := NewComplianceConnector(signUrlB, ArubaV1Notary, "23.10", raw, "did:web:vc.mivp.group", "did:web:vc.mivp.group#X509-JWK2020")
	if err != nil {
		t.Fatal(err)
	}

	vc := &verifiableCredentials.VerifiableCredential{}

	err = json.Unmarshal([]byte(exampleSD2210), vc)
	if err != nil {
		t.Fatal(err)
	}

	err = c.SelfSign(vc)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, nil, c.SelfVerify(vc))
	assert.NoError(t, vc.Verify())
}
