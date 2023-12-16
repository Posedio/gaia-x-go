/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package compliance

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"os"
	"testing"
)

var validate *validator.Validate

func TestServiceOfferingSigned(t *testing.T) {
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

	c, err := NewComplianceConnector(MainBranch, ArubaV1Notary, "22.10", raw, "did:web:vc.mivp.group", "did:web:vc.mivp.group#X509-JWK2020")
	if err != nil {
		t.Fatal(err)
	}

	validate = validator.New()

	tc, err := c.SelfSignSignTermsAndConditions("https://vc.mivp.group/sd/tc.json")
	if err != nil {
		t.Fatal(err)
	}

	err = validate.Struct(tc)
	if err != nil {
		t.Fatal(err)
	}

	lrnOptions := LegalRegistrationNumberOptions{
		Id:                 "https://vc.mivp.group/sd/legalRegistrationNumberVC.json",
		RegistrationNumber: "ATU37675002",
		Type:               VatID,
	}

	number, err := c.SignLegalRegistrationNumber(lrnOptions)
	if err != nil {
		t.Fatal(err)
	}

	err = validate.Struct(number)
	if err != nil {
		t.Fatal(err)
	}

	toJson, err := number.ToJson()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(toJson))

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
		"id": "https://vc.mivp.group/sd/participant.json",
	}}

	participant, err := c.SelfSignCredentialSubject("https://vc.mivp.group/sd/participant.json", cred)
	if err != nil {
		t.Fatal(err)
	}

	err = validate.Struct(participant)
	if err != nil {
		t.Fatal(err)
	}

	oc := []map[string]interface{}{{
		"type": "gx:ServiceOffering",
		"gx:providedBy": map[string]interface{}{
			"id": "https://vc.mivp.group/sd/participant.json"},
		"gx:policy": "",
		"gx:termsAndConditions": map[string]interface{}{
			"gx:URL":  "http://termsandconds.com",
			"gx:hash": "d8402a23de560f5ab34b22d1a142feb9e13b3143",
		},
		"gx:dataAccountExport": map[string]interface{}{
			"gx:requestType": "API",
			"gx:accessType":  "digital",
			"gx:formatType":  "application/json",
		},
		"id": "https://vc.mivp.group/sd/offering.json",
	}}

	options := ServiceOfferingComplianceOptions{
		Id: "https://vc.mivp.group/sd/offering.json",
		ServiceOfferingOptions: ServiceOfferingOptionsAsMap{
			ServiceOfferingCredentialSubject: oc,
		},
		ParticipantComplianceOptions: ParticipantComplianceOptions{
			Id:                        "https://vc.mivp.group/sd/participant.json",
			TermAndConditionsVC:       tc,
			LegalRegistrationNumberVC: number,
			Participant: ParticipantOptionsAsMap{
				ParticipantCredentialSubject: cred,
			},
		},
	}

	serviceOffering, vps, err := c.SignServiceOffering(options)
	if err != nil {
		t.Fatal(err)
	}

	err = validate.Struct(vps)
	if err != nil {
		t.Fatal(err)
	}

	marshalIndent, err := json.MarshalIndent(vps, "", "	")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(marshalIndent))

	indent, err := json.MarshalIndent(serviceOffering, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(indent))

	err = serviceOffering.Verify()
	if err != nil {
		t.Fatal(err)
	}

}
