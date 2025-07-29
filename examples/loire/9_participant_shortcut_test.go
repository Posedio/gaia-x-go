/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/
package loire

import (
	"github.com/Posedio/gaia-x-go/compliance"
	"github.com/Posedio/gaia-x-go/gxTypes"
	"github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"testing"
)

func TestCompliantParticipant(t *testing.T) {
	// to retrieve a compliant participant credential, as described before a digital identity in this case a DID is needed

	// to establish a client we follow the steps we had already done
	connector, err := compliance.NewComplianceConnectorV2(
		compliance.Endpoints{Compliance: compliance.V2Staging, Notary: compliance.DeltaDaoV2Notary},
		"loire",
		&compliance.IssuerSetting{
			Key:                key,
			Alg:                jwa.PS256,
			Issuer:             "did:web:did.dumss.me",
			VerificationMethod: "did:web:did.dumss.me#v1-2025",
		})
	if err != nil {
		t.Fatal(err)
	}

	lrnOptions := compliance.LegalRegistrationNumberOptions{
		Id:                 "http://lrn.test", // Id for the VerifiableCredential that it can be unique identified
		RegistrationNumber: "ATU75917607",
		Type:               compliance.VatID,
	}

	// retrieve the Legal Registration Number VC with the provided options
	legalRegistrationNumberVC, err := connector.SignLegalRegistrationNumber(lrnOptions)
	if err != nil {
		t.Fatal(err)
	}

	// same as before a valid the terms and conditions have to be accepted
	conditions, err := connector.SignTermsAndConditions("http://signedTC.test")
	if err != nil {
		t.Fatal(err)
	}

	pco := compliance.ParticipantComplianceOptions{
		Id: "https://acme.org", //the id of the future verifiable credential
		Participant: compliance.ParticipantV2Options{ //adds the participant information as a map
			LegalPerson: gxTypes.LegalPerson{
				// we just add the Credential Subject ID of the legal registration number vc, pay attention since there is currently a shape bug on the main version of the lab instance the LEI Code does not work
				RegistrationNumber: gxTypes.RegistrationNumberID{CredentialSubjectShape: verifiableCredentials.CredentialSubjectShape{ID: legalRegistrationNumberVC.ID + "#CS"}},
				//Name:               "test",
				// we can now use the generated address with id for the headquarters address
				// to specify that the input we provide is ob type gx:Address we have to add this to the
				HeadquartersAddress: gxTypes.Address{
					//CredentialSubjectShape: verifiableCredentials.CredentialSubjectShape{ID: addressVC.ID + "#cs"},
					CountryCode:   "AT",
					CountryName:   "Austria",
					PostalCode:    "1040",
					StreetAddress: "Weyringergasse 1-3/DG ",
					Locality:      "Vienna",
				},
				// we can now use the generated address with id for the legal address
				// to specify that the input we provide is ob type gx:Address we have to add this to the
				LegalAddress: gxTypes.Address{
					//CredentialSubjectShape: verifiableCredentials.CredentialSubjectShape{ID: addressVC.ID + "#cs"},
					CountryCode:   "AT",
					CountryName:   "Austria",
					PostalCode:    "1040",
					StreetAddress: "Weyringergasse 1-3/DG ",
					Locality:      "Vienna",
				}}},
		LegalRegistrationNumberVC: legalRegistrationNumberVC, //reference to the legal registration number vc
		TermAndConditionsVC:       conditions,                // reference to the accepted terms and conditions vc
	}

	vc, vp, err := connector.GaiaXSignParticipant(pco)
	if err != nil {
		if vp != nil {
			t.Log(string(vp.GetOriginalJWS()))
		}

		t.Fatal(err)
	}

	// presented verifiable presentation to the compliance server
	t.Log(string(vp.GetOriginalJWS()))

	// retrieved verifiable credential from the compliance server
	t.Log(vc)

	err = vc.Verify()
	if err != nil {
		t.Fatal(err)
	}

	err = vc.Verify(verifiableCredentials.UseOldSignAlgorithm())
	if err != nil {
		t.Fatal(err)
	}
}
