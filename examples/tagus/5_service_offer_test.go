/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/
package loire

import (
	"github.com/Posedio/gaia-x-go/compliance"
	vc "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"testing"
)

func TestCompliantServiceOffering(t *testing.T) {
	// to retrieve a compliant participant credential, as described before a digital identity in this case a DID is needed

	// to establish a client we follow the steps we had already done

	connector, err := compliance.NewComplianceConnectorV2(
		compliance.Endpoints{
			Compliance: compliance.V1Staging,
			Notary:     compliance.DeltaDaoV1Notary},
		"tagus",
		&compliance.IssuerSetting{
			Key:                key,
			Alg:                jwa.PS256,
			Issuer:             "did:web:did.dumss.me",
			VerificationMethod: "did:web:did.dumss.me#v1-2025",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// options a built as before, see 2 first gaia-x verifiable credential
	lrnOptions := compliance.LegalRegistrationNumberOptions{
		Id:                 "http://lrn.test",      // Id for the VerifiableCredential that it can be unique identified
		RegistrationNumber: "98450045E09C7F5A0703", // Legal Registration Number in this case the on of the GAIA-X AISBL
		Type:               compliance.LeiCode,     // Type of the Legal Registration NUmber see List above
	}

	// retrieve the Legal Registration Number VC with the provided options
	legalRegistrationNumberVC, err := connector.SignLegalRegistrationNumber(lrnOptions)
	if err != nil {
		t.Fatal(err)
	}

	err = legalRegistrationNumberVC.Verify(vc.IsGaiaXTrustedIssuer(compliance.CISPEV1Notary.String()))
	if err != nil {
		t.Fatal(err)
	}

	// same as before a valid the terms and conditions have to be accepted
	conditions, err := connector.SelfSignSignTermsAndConditions("http://signedTC.test")
	if err != nil {
		t.Fatal(err)
	}

	// same as before the shape for the offering can be retrieved from https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#
	oc := []map[string]interface{}{{
		"type": "gx:ServiceOffering", // required to be identified as a service offering shape
		"gx:providedBy": map[string]interface{}{ // required
			"id": "https://acme.org"}, // the id of the gaia-x participant that provides the offering
		"gx:policy": "", // a policy has to set, or at least to be set on purpose set to nothing
		"gx:termsAndConditions": map[string]interface{}{ // required, a resolvable link to the service offering self-description related to the service and that can exist independently of it.
			"gx:URL":  "http://termsandconds.com",                 // required, a resolvable link to document
			"gx:hash": "d8402a23de560f5ab34b22d1a142feb9e13b3143", //required, sha256 hash of the above document.
		},
		"gx:dataAccountExport": map[string]interface{}{ // required, list of methods to export data from your user’s account out of the service
			"gx:requestType": "API",              // required, one of: "API","email","webform","unregisteredLetter","registeredLetter","supportCenter"
			"gx:accessType":  "digital",          // required, digital or physical
			"gx:formatType":  "application/json", // required, type of Media Types (formerly known as MIME types) as defined by the IANA
		},
		"id": "https://some-acme-offering.org", // required, id of the service offering credential subject
	}}

	options := compliance.ServiceOfferingComplianceOptions{
		Id: "https://vc.mivp.group/sd/offering.json", // id of the service offering credential subject
		ServiceOfferingOptions: compliance.ServiceOfferingOptionsAsMap{ // config in form of a map
			ServiceOfferingCredentialSubject: oc, //the above set map
		},
		ParticipantComplianceOptions: compliance.ParticipantComplianceOptions{ //see unit 4 participant
			Id: "https://acme.org",
			Participant: compliance.ParticipantOptionsAsMap{
				ParticipantCredentialSubject: []map[string]interface{}{{
					"type": "gx:LegalParticipant",
					//"gx:legalName": "Gaia-X European Association for Data and Cloud AISBL",
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

	offering, vp, err := connector.SignServiceOffering(options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(vp)

	t.Log(offering)

}
