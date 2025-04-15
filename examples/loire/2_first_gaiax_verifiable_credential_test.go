/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package loire

import (
	"github.com/Posedio/gaia-x-go/compliance"
	vc "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/go-playground/validator/v10"
	"testing"
)

func TestFirstComplianceCredential(t *testing.T) {
	// to retrieve the first Gaia-X credential, only the endpoint for the notary part of the Gaia-x Clearing Houses is needed
	// rest can be empty for now. It is possible to choose from: compliance.LabV1, compliance.ArubaV1Notary and compliance.TSystemV1
	connector, err := compliance.NewComplianceConnector("", compliance.TSystemV2Notary, "loire", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// to retrieve the first verifiable credential a legal registration number has to be provided this could be in the form of
	// compliance.VatID, compliance.LeiCode, compliance.EUID, compliance.EORI,or compliance.TaxID
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

	t.Log(legalRegistrationNumberVC)

	err = legalRegistrationNumberVC.Validate(validator.New())
	if err != nil {
		t.Fatal(err)
	}

	err = legalRegistrationNumberVC.Verify(vc.IsGaiaXTrustedIssuer(compliance.TSystemV2Notary.String()), vc.IssuerMatch()) //cross check with other notary
	if err != nil {
		t.Fatal(err)
	}

}
