/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package examples

import (
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/compliance"
	"testing"
)

func TestCompliantServiceOffering(t *testing.T) {
	// to retrieve a compliant participant credential, as described before a digital identity in this case a DID is needed
	// so first loading the private key is needed
	privateKey := getKey(t)

	// to establish a client we follow the steps we had already done
	connector, err := compliance.NewComplianceConnector(compliance.V1Staging, compliance.ArubaV1Notary, "22.10", privateKey, "did:web:vc.mivp.group", "did:web:vc.mivp.group#X509-JWK2020")
	if err != nil {
		t.Fatal(err)
	}

	lrnOptions := compliance.LegalRegistrationNumberOptions{
		Id:                 "http://lrn.test", // Id for the VerifiableCredential that it can be unique identified
		RegistrationNumber: "FR79537407926",   // Legal Registration Number in this case the on of the GAIA-X AISBL
		Type:               compliance.VatID,  // Type of the Legal Registration NUmber see List above
	}

	// retrieve the Legal Registration Number VC with the provided options
	legalRegistrationNumberVC, err := connector.SignLegalRegistrationNumber(lrnOptions)
	if err != nil {
		t.Fatal(err)
	}

	conditions, err := connector.SelfSignSignTermsAndConditions("http://signedTC.test")
	if err != nil {
		t.Fatal(err)
	}

	oc := []map[string]interface{}{{
		"type": "gx:ServiceOffering",
		"gx:providedBy": map[string]interface{}{
			"id": "https://acme.org"},
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

	options := compliance.ServiceOfferingComplianceOptions{
		Id: "https://vc.mivp.group/sd/offering.json",
		ServiceOfferingOptions: compliance.ServiceOfferingOptionsAsMap{
			ServiceOfferingCredentialSubject: oc,
		},
		ParticipantComplianceOptions: compliance.ParticipantComplianceOptions{
			Id: "https://acme.org",
			Participant: compliance.ParticipantOptionsAsMap{
				ParticipantCredentialSubject: []map[string]interface{}{{
					"type":         "gx:LegalParticipant",
					"gx:legalName": "Gaia-X European Association for Data and Cloud AISBL",
					"gx:legalRegistrationNumber": map[string]interface{}{
						"id": legalRegistrationNumberVC.ID,
					},
					"gx:headquarterAddress": map[string]interface{}{
						"gx:countrySubdivisionCode": "BE-BRU",
					},
					"gx:legalAddress": map[string]interface{}{
						"gx:countrySubdivisionCode": "BE-BRU",
					},
					"id": "https://acme.org",
				}},
			},
			LegalRegistrationNumberVC: legalRegistrationNumberVC,
			TermAndConditionsVC:       conditions,
		},
	}

	offering, _, err := connector.SignServiceOffering(options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(offering)

}
