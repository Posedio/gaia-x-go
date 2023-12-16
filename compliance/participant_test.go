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

func TestParticipantSigned(t *testing.T) {
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

	tc, err := c.SelfSignSignTermsAndConditions("https://vc.mivp.group/sd/tc.json")
	if err != nil {
		t.Fatal(err)
	}

	lrnOptions := LegalRegistrationNumberOptions{
		Id:                 "https://vc.mivp.group/sd/legalRegistrationNumberVC.json",
		RegistrationNumber: "ATU37675002",
		Type:               VatID,
	}

	numberVC, err := c.SignLegalRegistrationNumber(lrnOptions)
	if err != nil {
		t.Fatal(err)
	}

	numberJ, err := numberVC.ToJson()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(numberJ))

	cred := []map[string]interface{}{{
		"type":         "gx:LegalParticipant",
		"gx:legalName": "Gaia-X European Association for Data and Cloud AISBL",
		"gx:legalRegistrationNumber": map[string]interface{}{
			"id": "https://vc.mivp.group/sd/legalRegistrationNumberVC.json",
		},
		"gx:headquarterAddress": map[string]interface{}{
			"gx:countrySubdivisionCode": "BE-BRU",
		},
		"gx:legalAddress": map[string]interface{}{
			"gx:countrySubdivisionCode": "BE-BRU",
		},
		"id": "https://test.test.test#participant",
	}}

	pco := ParticipantComplianceOptions{
		Id:                        "https://test.test.test#participant",
		LegalRegistrationNumberVC: numberVC,
		TermAndConditionsVC:       tc,
		Participant: ParticipantOptionsAsMap{
			ParticipantCredentialSubject: cred,
		},
	}

	participant, _, err := c.GaiaXSignParticipant(pco)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", participant)

	err = participant.Verify()
	if err != nil {
		t.Fatal(err)
	}

}
