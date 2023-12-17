/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package examples

import (
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/compliance"
	"testing"
)

func TestCompliantParticipant(t *testing.T) {
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

	// same as before a valid the terms and conditions have to be accepted
	conditions, err := connector.SelfSignSignTermsAndConditions("http://signedTC.test")
	if err != nil {
		t.Fatal(err)
	}

	pco := compliance.ParticipantComplianceOptions{
		Id: "https://acme.org", //the id of the future verifiable credential
		Participant: compliance.ParticipantOptionsAsMap{ //adds the participant information as a map
			ParticipantCredentialSubject: []map[string]interface{}{{
				"type": "gx:LegalParticipant", //required to type the credential subject as a LegalParticipant
				//"gx:legalName": "Gaia-X European Association for Data and Cloud AISBL", //is not required and in fact not part of the ontology
				"gx:legalRegistrationNumber": map[string]interface{}{ //required
					"id": legalRegistrationNumberVC.ID, //id of the legal registration number vc
				},
				"gx:headquarterAddress": map[string]interface{}{ // required
					"gx:countrySubdivisionCode": "BE-BRU", // required, an ISO 3166-2 format value is expected.
				},
				"gx:legalAddress": map[string]interface{}{ // required
					"gx:countrySubdivisionCode": "BE-BRU", // required, an ISO 3166-2 format value is expected.
				},
				"id": "https://acme.org", //id of the future participant vc
			},
			}},
		LegalRegistrationNumberVC: legalRegistrationNumberVC, //reference to the legal registration number vc
		TermAndConditionsVC:       conditions,                // reference to the accepted terms and conditions vc
	}

	vc, vp, err := connector.GaiaXSignParticipant(pco)
	if err != nil {
		t.Fatal(err)
	}

	// presented verifiable presentation to the compliance server
	t.Log(vp)

	// retrieved verifiable credential from the compliance server
	t.Log(vc)
}
