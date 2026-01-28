/*
MIT License
Copyright (c) 2026 Stefan Dumss, Posedio GmbH
*/

package loire

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Posedio/gaia-x-go/compliance"
	"github.com/Posedio/gaia-x-go/gxTypes"
	"github.com/Posedio/gaia-x-go/signer"
	vc "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

func TestNewDataProduct(t *testing.T) {
	var idprefix = "https://did.dumss.me/"
	var issuer = "did:web:did.dumss.me"
	var countryCode = "AT"
	var countryName = "Austria"

	u := compliance.V2Staging.StatusURL()

	get, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(get.Body)
	body, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(body))

	connector, err := compliance.NewComplianceConnectorV3(
		compliance.Endpoints{Compliance: compliance.V2Staging, Notary: compliance.DeltaDaoV2Notary},
		"loire",
		&signer.JWTSigner{
			Issuer: &signer.IssuerSetting{
				Key:                key,
				Alg:                jwa.PS256(),
				Issuer:             issuer,
				VerificationMethod: "did:web:did.dumss.me#v3-2025",
			},
			Client: &http.Client{
				Timeout: 90 * time.Second,
			},
		})
	if err != nil {
		t.Fatal(err)
	}

	//prepare Verifiable Presentation
	vp := vc.NewEmptyVerifiablePresentationV2()

	//participant
	//accept the terms and conditions of Gaia-X for the compliance
	//Gaia-X terms and conditions
	tcVC, err := connector.SignTermsAndConditions(idprefix + "tc")
	if err != nil {
		t.Fatal(err)
	}

	err = tcVC.Verify(vc.IssuerMatch())
	if err != nil {
		t.Fatal(err)
	}

	//retrieve the legal registration number vc from the GXDCH
	LRNVC, err := connector.SignLegalRegistrationNumber(compliance.LegalRegistrationNumberOptions{
		Id: idprefix + "LRN",
		//RegistrationNumber: "ATU75917607",
		RegistrationNumber: "391200FJBNU0YW987L26",
		//Type:               compliance.VatID,
		Type: compliance.LeiCode,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log(LRNVC)

	time.Sleep(100 * time.Millisecond) //if time sync is a little off
	// verify the credential (not needed but recommended)
	err = LRNVC.Verify(vc.IssuerMatch(), vc.IsGaiaXTrustedIssuer(compliance.DeltaDAORegistryV2.TrustedIssuer()))
	if err != nil {
		t.Fatal(err)
	}

	//add the credential to the verifiable presentation as EnvelopedVerifiableCredential
	vp.AddEnvelopedVC(LRNVC.GetOriginalJWS())

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
	}

	// add the Address to the VC as CredentialSubject, technically you can combine multiple types and credentials into
	// one vc. To make it easier to understand, we will only add one by one for now
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

	// Legal Binding Documents
	DocumentChangeProceduresVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"DocumentChangeProcedures"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:DocumentChangeProcedures"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	DocumentChangeProcedures := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/DocumentChangeProcedures"),
	}
	DocumentChangeProcedures.ID = DocumentChangeProceduresVC.ID + "#cs"
	err = DocumentChangeProceduresVC.AddToCredentialSubject(DocumentChangeProcedures)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(DocumentChangeProceduresVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(DocumentChangeProceduresVC.GetOriginalJWS())

	// Data Product
	dataProductVC, err := vc.NewEmptyVerifiableCredentialV2(
		vc.WithIssuer(issuer),
		vc.WithValidFromNow(),
		vc.WithGaiaXContext(),
		vc.WithAdditionalTypes("gx:DataProduct"),
	)
	if err != nil {
		t.Fatal(err)
	}
	dataProductVC.ID = idprefix + "offeringVC"

	dataProductCS := gxTypes.DataProduct2511{
		DataProductDescription: gxTypes.DataProductDescription2511{
			DataSets: []string{"test"},
			DataProductConfigurationParameters: []gxTypes.DataProductConfigurationParameter{{
				ParameterName:             "test",
				ParameterDescription:      "test",
				ParameterAdmissibleValues: []string{"test"},
			}},
		},
		DigitalServiceOffering: gxTypes.DigitalServiceOffering{
			DigitalServiceOfferingName:               "test",
			DigitalServiceOfferingShortDescription:   "test",
			DigitalServiceOfferingProvider:           gxTypes.LegalPerson{Participant: gxTypes.Participant{GaiaXEntity: gxTypes.GaiaXEntity{CredentialSubjectShape: vc.CredentialSubjectShape{ID: companyCS.ID, Type: "gx:LegalPerson"}}}},
			DigitalServiceOfferingIdentifier:         "test",
			DigitalServiceOfferingLaunchDate:         "28.01.2025",
			DigitalServiceOfferingTermsAndConditions: gxTypes.TermsAndConditions{CredentialSubjectShape: vc.CredentialSubjectShape{Type: "gx:ServiceTermsAndConditions"}, URL: vc.WithAnyURI("https://www.posedio.com/TermsAndConditions"), Hash: "abc"},
			DigitalServiceUsageTermsAndConditions:    gxTypes.TermsAndConditions{CredentialSubjectShape: vc.CredentialSubjectShape{Type: "gx:UsageTermsAndConditions"}, URL: vc.WithAnyURI("https://www.posedio.com/TermsAndConditions"), Hash: "abc"},
			DigitalServiceUsageDataPolicy:            gxTypes.TermsAndConditions{CredentialSubjectShape: vc.CredentialSubjectShape{Type: "gx:TermsAndConditions"}, URL: vc.WithAnyURI("https://www.posedio.com/TermsAndConditions"), Hash: "abc"},
			DigitalServiceLegalDocuments:             []gxTypes.LegalDocument{},
		},
	}
	dataProductCS.AddLegalDocumentURI(DocumentChangeProcedures.ID)

	dataProductCS.ID = dataProductVC.ID + "#CS"

	err = dataProductVC.AddToCredentialSubject(dataProductCS)
	if err != nil {
		t.Fatal(err)
	}

	dataProductVC.ID = idprefix + "offeringVC"

	dataProductVC.ValidFrom = vc.TimeNow()

	err = connector.SelfSign(dataProductVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(dataProductVC.GetOriginalJWS())

	offering, _, err := connector.SignServiceOffering(compliance.ServiceOfferingComplianceOptions{ServiceOfferingVP: vp, ServiceOfferingLabelLevel: compliance.Level0, Id: idprefix + "complianceCredential"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(offering)

	t.Log(string(vp.GetOriginalJWS()))

}
