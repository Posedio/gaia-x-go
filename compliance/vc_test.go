/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package compliance

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/assert"
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/did"
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/verifiableCredentials"
)

var credCheck = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#"
  ],
  "type": [
    "VerifiableCredential"
  ],
  "id": "https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203",
  "issuer": "did:web:compliance.lab.gaia-x.eu:v1",
  "issuanceDate": "2023-10-17T18:57:17.903Z",
  "expirationDate": "2024-01-15T18:57:17.903Z",
  "credentialSubject": [
    {
      "type": "gx:compliance",
      "id": "https://www.delta-dao.com/.well-known/2210_service_AutoTiM_Application_1.json",
      "gx:integrity": "sha256-24688e8deb337bd14f1e3b4c7889a1e442be5321c90c9bf13bd140c6b555d78c",
      "gx:integrityNormalization": "RFC8785:JCS",
      "gx:version": "22.10",
      "gx:type": "gx:ServiceOffering"
    },
    {
      "type": "gx:compliance",
      "id": "https://www.delta-dao.com/.well-known/2210_gx_participant_Inovex.json",
      "gx:integrity": "sha256-1e1313a8c22aa00842a8b88a0d4aa709470e53695de4d7f0758f2272f0554cd6",
      "gx:integrityNormalization": "RFC8785:JCS",
      "gx:version": "22.10",
      "gx:type": "gx:LegalParticipant"
    },
    {
      "type": "gx:compliance",
      "id": "https://www.delta-dao.com/.well-known/2210_gx_registrationnumber_Inovex.json",
      "gx:integrity": "sha256-fb5ded9480224a607d2df9d480d65d28a671514aa66390d8c0856af591a6baba",
      "gx:integrityNormalization": "RFC8785:JCS",
      "gx:version": "22.10",
      "gx:type": "gx:legalRegistrationNumber"
    },
    {
      "type": "gx:compliance",
      "id": "https://www.delta-dao.com/.well-known/2210_gx_tandc_Inovex.json",
      "gx:integrity": "sha256-c534ebfab7614a073687d1cc26b31c191d2578fb18e08614f33049ad6bff5920",
      "gx:integrityNormalization": "RFC8785:JCS",
      "gx:version": "22.10",
      "gx:type": "gx:GaiaXTermsAndConditions"
    }
  ],
  "proof": {
    "type": "JsonWebSignature2020",
    "created": "2023-10-17T18:57:17.912Z",
    "proofPurpose": "assertionMethod",
    "jws": "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..UeNV-lPxrY_D7P9zcaC-OhFIBhVHcuYt3la2fDbR5xbV4BCv7Ao_1bdV4-nN4qQrOF27nvTjZWBQp21vNYVfYKyV8d9cTaJd5HszEI1ymSiXGNtQCIwUqfgrk5kXNAIbQXgZiualLj57BbPPEuoQAerirGWj8j72Q1AqamtYgKXD8MsbJYuw5uYzHGjPLORNP-C3uy2rQDXPW-bf_GtftI4qfwOGgvh7LFAvn71yURB2BRXhfe0DE-NGPCD9JkzH6ilcr5Ll3EsBKw_2w-vFgmEs6IYGqVoQIMRiiOLnq1sY6U0k8sOn25ahMbd7_UFwF2yMLaWOQ7L1jPjB_72Lbw",
    "verificationMethod": "did:web:compliance.lab.gaia-x.eu:v1#X509-JWK2020"
  }
}
`

var jsNorm = `<did:op:07608944212053188f448a6468743b0676721a3b3ec178f13eb805a0accd7169> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#compliance> .
<did:op:07608944212053188f448a6468743b0676721a3b3ec178f13eb805a0accd7169> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#integrity> "sha256-b1a01a15dd7f9da7f824efbad4dfee70ea80a6e8a7585a5ee3a48bd410bf2cc3" .
<did:op:07608944212053188f448a6468743b0676721a3b3ec178f13eb805a0accd7169> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#integrityNormalization> "RFC8785:JCS" .
<did:op:07608944212053188f448a6468743b0676721a3b3ec178f13eb805a0accd7169> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#type> "gx:ServiceOffering" .
<did:op:07608944212053188f448a6468743b0676721a3b3ec178f13eb805a0accd7169> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#version> "22.10" .
<https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203> <https://www.w3.org/2018/credentials#credentialSubject> <did:op:07608944212053188f448a6468743b0676721a3b3ec178f13eb805a0accd7169> .
<https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203> <https://www.w3.org/2018/credentials#credentialSubject> <https://www.delta-dao.com/.well-known/2210_gx_participant_Inovex.json> .
<https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203> <https://www.w3.org/2018/credentials#credentialSubject> <https://www.delta-dao.com/.well-known/2210_gx_registrationnumber_Inovex.json> .
<https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203> <https://www.w3.org/2018/credentials#credentialSubject> <https://www.delta-dao.com/.well-known/2210_gx_tandc_Inovex.json> .
<https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203> <https://www.w3.org/2018/credentials#expirationDate> "2023-12-18T20:03:03.925Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203> <https://www.w3.org/2018/credentials#issuanceDate> "2023-09-19T20:03:03.925Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203> <https://www.w3.org/2018/credentials#issuer> <did:web:compliance.lab.gaia-x.eu:v1> .
<https://www.delta-dao.com/.well-known/2210_gx_participant_Inovex.json> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#compliance> .
<https://www.delta-dao.com/.well-known/2210_gx_participant_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#integrity> "sha256-1e1313a8c22aa00842a8b88a0d4aa709470e53695de4d7f0758f2272f0554cd6" .
<https://www.delta-dao.com/.well-known/2210_gx_participant_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#integrityNormalization> "RFC8785:JCS" .
<https://www.delta-dao.com/.well-known/2210_gx_participant_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#type> "gx:LegalParticipant" .
<https://www.delta-dao.com/.well-known/2210_gx_participant_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#version> "22.10" .
<https://www.delta-dao.com/.well-known/2210_gx_registrationnumber_Inovex.json> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#compliance> .
<https://www.delta-dao.com/.well-known/2210_gx_registrationnumber_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#integrity> "sha256-fb5ded9480224a607d2df9d480d65d28a671514aa66390d8c0856af591a6baba" .
<https://www.delta-dao.com/.well-known/2210_gx_registrationnumber_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#integrityNormalization> "RFC8785:JCS" .
<https://www.delta-dao.com/.well-known/2210_gx_registrationnumber_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#type> "gx:legalRegistrationNumber" .
<https://www.delta-dao.com/.well-known/2210_gx_registrationnumber_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#version> "22.10" .
<https://www.delta-dao.com/.well-known/2210_gx_tandc_Inovex.json> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#compliance> .
<https://www.delta-dao.com/.well-known/2210_gx_tandc_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#integrity> "sha256-c534ebfab7614a073687d1cc26b31c191d2578fb18e08614f33049ad6bff5920" .
<https://www.delta-dao.com/.well-known/2210_gx_tandc_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#integrityNormalization> "RFC8785:JCS" .
<https://www.delta-dao.com/.well-known/2210_gx_tandc_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#type> "gx:GaiaXTermsAndConditions" .
<https://www.delta-dao.com/.well-known/2210_gx_tandc_Inovex.json> <https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#version> "22.10" .
`

var arubaOld = `
{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
        "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#"
      ],
      "type": [
        "VerifiableCredential"
      ],
      "id": "https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203",
      "issuer": "did:web:compliance.lab.gaia-x.eu:v1",
      "issuanceDate": "2023-09-19T20:03:03.925Z",
      "expirationDate": "2023-12-18T20:03:03.925Z",
      "credentialSubject": [
        {
          "type": "gx:compliance",
          "id": "did:op:07608944212053188f448a6468743b0676721a3b3ec178f13eb805a0accd7169",
          "gx:integrity": "sha256-b1a01a15dd7f9da7f824efbad4dfee70ea80a6e8a7585a5ee3a48bd410bf2cc3",
          "gx:integrityNormalization": "RFC8785:JCS",
          "gx:version": "22.10",
          "gx:type": "gx:ServiceOffering"
        },
        {
          "type": "gx:compliance",
          "id": "https://www.delta-dao.com/.well-known/2210_gx_participant_Inovex.json",
          "gx:integrity": "sha256-1e1313a8c22aa00842a8b88a0d4aa709470e53695de4d7f0758f2272f0554cd6",
          "gx:integrityNormalization": "RFC8785:JCS",
          "gx:version": "22.10",
          "gx:type": "gx:LegalParticipant"
        },
        {
          "type": "gx:compliance",
          "id": "https://www.delta-dao.com/.well-known/2210_gx_registrationnumber_Inovex.json",
          "gx:integrity": "sha256-fb5ded9480224a607d2df9d480d65d28a671514aa66390d8c0856af591a6baba",
          "gx:integrityNormalization": "RFC8785:JCS",
          "gx:version": "22.10",
          "gx:type": "gx:legalRegistrationNumber"
        },
        {
          "type": "gx:compliance",
          "id": "https://www.delta-dao.com/.well-known/2210_gx_tandc_Inovex.json",
          "gx:integrity": "sha256-c534ebfab7614a073687d1cc26b31c191d2578fb18e08614f33049ad6bff5920",
          "gx:integrityNormalization": "RFC8785:JCS",
          "gx:version": "22.10",
          "gx:type": "gx:GaiaXTermsAndConditions"
        }
      ],
      "proof": {
        "type": "JsonWebSignature2020",
        "created": "2023-09-19T20:03:03.933Z",
        "proofPurpose": "assertionMethod",
        "jws": "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..Tza6aF5_3QnubpUdVmBgvsGm_UblRLMnFOZabC6fos3JY52g9RV4GJ0pF74B_XECVo-w-8PFO3skHfvggp9h0cqW4cN_UDdLGZPvM3lBJ2uGigZCFhAb3xSF2r2Mn0tE1VeNX1xr9qtfrkI-BGB6M7aSFVZ7lSoPm9aTS025kh61c273b8y4G-FyyrwR8UgcCY9_BATui32dEWnC0ZFHkUv0KSjBy4B1Hbzb67G5bd5g-ZVzQgUG4EMKzvDt5g-Ydh-FOxtd6M4MBXWsvI71JPyMmA4v-n2mG-snWsfExAin8GVo0SBap8x9k3wUf23tpExN8-swd9oLMQ596njXuw",
        "verificationMethod": "did:web:compliance.lab.gaia-x.eu:v1#X509-JWK2020"
      }
}
`

func TestVCLoad(t *testing.T) {

	client := &http.Client{
		Timeout: 5 * time.Second,
		/*
			CheckRedirect: func(req *http.Request, via []*http.Request) error { //redirects are not the point of dids so prevented
				return http.ErrUseLastResponse
			}
		*/
	}

	req, err := http.NewRequest("GET", "https://www.delta-dao.com/.well-known/2210_gx_participant.json", nil)
	if err != nil {
		t.Fatalf("Error Occurred. %+v", err)
	}

	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request to API endpoint. %+v", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	if response.StatusCode != 200 {
		e := fmt.Sprintf("Server responded with %v not with 200 (OK) status code", response.StatusCode)
		t.Fatal(e)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("Couldn't parse response body. %+v", err)
	}

	vp := &verifiableCredentials.VerifiablePresentation{}

	err = json.Unmarshal(body, vp)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range vp.VerifiableCredential {
		err = c.Verify()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestVC(t *testing.T) {

	c := &verifiableCredentials.VerifiableCredential{}

	//err := json.Unmarshal([]byte(cred), c)
	err := json.Unmarshal([]byte(arubaOld), c)
	if err != nil {
		t.Fatal(err)
	}
	err = c.Verify()
	if err != nil {
		t.Fatal(err)
	}
	transform, err := jcs.Transform([]byte(arubaOld))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(transform))

}

func TestCredCheck(t *testing.T) {

	c := &verifiableCredentials.VerifiableCredential{}

	err := json.Unmarshal([]byte(credCheck), c)
	if err != nil {
		t.Fatal(err)
	}

	hash := verifiableCredentials.GenerateHash([]byte(jsNorm))

	web, err := did.ResolveDIDWeb(c.Proof.Proofs[0].VerificationMethod)
	if err != nil {
		t.Log(c.Proof.Proofs[0].VerificationMethod)
		t.Fatal(err)
	}

	err = web.ResolveMethods()
	if err != nil {
		t.Fatal(err)
	}

	k := web.Keys[c.Proof.Proofs[0].VerificationMethod].JWK
	t.Logf("%+v", k)

	assert.Equal(t, c.Proof.Proofs[0].JWS, "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..UeNV-lPxrY_D7P9zcaC-OhFIBhVHcuYt3la2fDbR5xbV4BCv7Ao_1bdV4-nN4qQrOF27nvTjZWBQp21vNYVfYKyV8d9cTaJd5HszEI1ymSiXGNtQCIwUqfgrk5kXNAIbQXgZiualLj57BbPPEuoQAerirGWj8j72Q1AqamtYgKXD8MsbJYuw5uYzHGjPLORNP-C3uy2rQDXPW-bf_GtftI4qfwOGgvh7LFAvn71yURB2BRXhfe0DE-NGPCD9JkzH6ilcr5Ll3EsBKw_2w-vFgmEs6IYGqVoQIMRiiOLnq1sY6U0k8sOn25ahMbd7_UFwF2yMLaWOQ7L1jPjB_72Lbw")

	_, err = jws.Verify([]byte(c.Proof.Proofs[0].JWS), jws.WithKey(k.Algorithm(), k), jws.WithDetachedPayload([]byte(hash)))
	if err != nil {
		t.Log(err)
	}

	err = c.Verify()
	if err != nil {
		t.Fatal(err)
	}

}
