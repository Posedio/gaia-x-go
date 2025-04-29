package loire

import (
	"github.com/Posedio/gaia-x-go/compliance"
	"github.com/Posedio/gaia-x-go/gxTypes"
	vc "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"testing"
	"time"
)

func TestLegalPerson(t *testing.T) {
	var idprefix = "https://did.dumss.me/"
	var issuer = "did:web:did.dumss.me"
	var countryCode = "AT"
	var countryName = "Austria"

	// instantiate a Compliance Connector for the Loire release
	connector, err := compliance.NewComplianceConnector(compliance.V2Staging, compliance.DeltaDaoV2Notary, "loire", key, "did:web:did.dumss.me", "did:web:did.dumss.me#v1-2025")
	if err != nil {
		t.Fatal(err)
	}

	//prepare Verifiable Presentation
	vp := vc.NewEmptyVerifiablePresentationV2()

	//retrieve the legal registration number vc from the GXDCH
	LRNVC, err := connector.SignLegalRegistrationNumber(compliance.LegalRegistrationNumberOptions{
		Id:                 idprefix + "LRN",
		RegistrationNumber: "ATU75917607",
		Type:               compliance.VatID,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log(LRNVC)

	// verify the credential (not needed but recommended)
	err = LRNVC.Verify(vc.IssuerMatch(), vc.IsGaiaXTrustedIssuer(compliance.TSystemRegistryV2.TrustedIssuer()))
	if err != nil {
		t.Fatal(err)
	}

	//add the credential to the verifiable presentation as EnvelopedVerifiableCredential
	vp.AddEnvelopedVC(LRNVC.GetOriginalJWS())

	//accept the terms and conditions of Gaia-X for the compliance
	//Gaia-X terms and conditions
	tcVC, err := connector.SignTermsAndConditions(idprefix + "tc")
	if err != nil {
		t.Fatal(err)
	}

	//add the VC to the Verifiable Presentation
	vp.AddEnvelopedVC(tcVC.GetOriginalJWS())

	// now we can start to add everything for a service offering:

	// first
	// Add an Address of the Company, CSP,Provider,...
	// there could be many more addresses add as needed, for minimal usage one is enough
	// this will be used every time we need an address

	// generate a VerifiableCredential V2 with an id and of type gx:Address
	addressVC, err := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"address"),
		vc.WithValidFromNow(),
		vc.WithGaiaXContext(),
		vc.WithIssuer(issuer),
		vc.WithAdditionalTypes("gx:Address"),
		vc.WithValidFor(time.Hour*24*365))
	if err != nil {
		t.Fatal(err)
	}

	// use the struct for the Address, minimal it has to contain this fields but there are many more
	// check the struct for more information
	addressCS := gxTypes.Address{
		CredentialSubjectShape: vc.CredentialSubjectShape{ID: addressVC.ID + "#cs"},
		CountryCode:            countryCode,
		CountryName:            countryName,
		PostalCode:             "1040",
		StreetAddress:          "Weyringergasse 1-3/DG ",
		Locality:               "Vienna",
	}

	// add the Address to the VC as CredentialSubject, technically you can combine multiple types and credentials into
	// one vc. To make it easier to understand we will only add one by one for now
	err = addressVC.AddToCredentialSubject(addressCS)
	if err != nil {
		t.Fatal(err)
	}

	// self sign the VC with the connector
	err = connector.SelfSign(addressVC)
	if err != nil {
		t.Fatal(err)
	}

	// optional verify the VC can be resolved by a third party
	err = addressVC.Verify()
	if err != nil {
		t.Fatal(err)
	}

	//add the VC to the Verifiable Presentation
	vp.AddEnvelopedVC(addressVC.GetOriginalJWS())

	//legal Person which is used for every legal person needed
	companyVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"legalPerson"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:LegalPerson"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	companyVC.Context.Context = append(companyVC.Context.Context, vc.Namespace{
		Namespace: "schema",
		URL:       "https://schema.org/",
	})

	// with the LegalPerson struct we can define a legal person
	companyCS := gxTypes.LegalPerson{
		// we just add the Credential Subject ID of the legal registration number vc, pay attention since there is currently a shape bug on the main version of the lab instance the LEI Code does not work
		RegistrationNumber: gxTypes.RegistrationNumberID{CredentialSubjectShape: vc.CredentialSubjectShape{ID: LRNVC.ID + "#cs"}},

		// we can now use the generated address with id for the headquarters address
		// to specify that the input we provide is ob type gx:Address we have to add this to the
		HeadquartersAddress: gxTypes.Address{
			CredentialSubjectShape: vc.CredentialSubjectShape{ID: addressCS.ID, Type: "gx:Address"},
		},
		// we can now use the generated address with id for the legal address
		// to specify that the input we provide is ob type gx:Address we have to add this to the
		LegalAddress: gxTypes.Address{
			CredentialSubjectShape: vc.CredentialSubjectShape{ID: addressCS.ID, Type: "gx:Address"},
		},
	}

	companyCS.ID = companyVC.ID + "#cs"

	// optional add a name, this is only the verifiable credential name and is just for information not for
	// compliance
	companyCS.Name = "Posedio GmbH"

	err = companyVC.AddToCredentialSubject(companyCS)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(companyVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(companyVC.GetOriginalJWS())
	err = connector.SelfSignPresentation(vp, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(vp.GetOriginalJWS()))
}
