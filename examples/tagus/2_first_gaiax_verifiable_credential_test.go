/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package tagus

import (
	"testing"

	"github.com/Posedio/gaia-x-go/compliance"
)

func TestFirstComplianceCredential(t *testing.T) {
	// to retrieve the first Gaia-X credential, only the endpoint for the notary part of the Gaia-x Clearing Houses is needed
	// rest can be empty for now. It is possible to choose from: compliance.LabV1, compliance.ArubaV1Notary and compliance.TSystemV1
	connector, err := compliance.NewComplianceConnectorV2(
		compliance.Endpoints{Notary: compliance.DeltaDaoV1Notary},
		"tagus",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	// to retrieve the first verifiable credential a legal registration number has to be provided this could be in the form of
	// compliance.VatID, compliance.LeiCode, compliance.EUID, compliance.EORI,or compliance.TaxID
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

	t.Log(legalRegistrationNumberVC)

	err = legalRegistrationNumberVC.Verify()
	if err != nil {
		t.Fatal(err)
	}

}
