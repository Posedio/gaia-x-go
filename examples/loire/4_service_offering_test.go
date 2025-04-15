/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package loire

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"

	"github.com/Posedio/gaia-x-go/compliance"
	"github.com/Posedio/gaia-x-go/gxTypes"
	vc "github.com/Posedio/gaia-x-go/verifiableCredentials"
)

func TestCompliance(t *testing.T) {
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

	// optional add a name, this is only the verifiable credential name and is just for information not for
	// compliance
	companyVC.Name = "Posedio GmbH"

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

	err = companyVC.AddToCredentialSubject(companyCS)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(companyVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(companyVC.GetOriginalJWS())

	// now we're starting to fulfill all criteria
	// ___________________________________ criteria ___________________________________
	// Communication Security: Ensure the protection of information in networks and the corresponding information processing
	//systems.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p3110
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.10

	pointOfPresenceVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"PointOfPresence"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:PointOfPresence"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)

	// same as before now use the PointOfPresence struct
	pointOfPresenceCS := gxTypes.PointOfPresence{
		PhysicalResource: gxTypes.PhysicalResource{
			// required who is maintaining it, we add the company from before
			MaintainedBy: []gxTypes.LegalPerson{{Participant: gxTypes.Participant{GaiaXEntity: gxTypes.GaiaXEntity{CredentialSubjectShape: vc.CredentialSubjectShape{ID: companyCS.ID, Type: "gx:InternetServiceProvider"}}}}},
			// required a list of physical Location in the form of a gx:Address we will just add an empty one and fill it later
			Location: make([]gxTypes.Address, 1),
			// required who owns the resource which will be again the company set above
			OwnedBy: []gxTypes.LegalPerson{{Participant: gxTypes.Participant{GaiaXEntity: gxTypes.GaiaXEntity{CredentialSubjectShape: vc.CredentialSubjectShape{ID: companyCS.ID, Type: "gx:LegalPerson"}}}}},
		},
		// does not work with the current main version
		// Participants: []LegalPerson{{Participant: Participant{GaiaXEntity: GaiaXEntity{CredentialSubjectShape: CredentialSubjectShape{ID: companyCS.ID, Type: "gx:LegalPerson"}}}}},

		// Required: Definition of the location where resources can interconnect
		InterconnectionPointIdentifier: gxTypes.InterconnectionPointIdentifier{
			// Required: Unique label identifying structure of an IPI, e.g. IP-Address
			CompleteIPI: "127.0.0.1",
			// since we define it nested without a new vc, we have to add the gx Type
			CredentialSubjectShape: vc.CredentialSubjectShape{Type: "gx:InterconnectionPointIdentifier"},
		},
	}

	// now we add our address from above as location:
	pointOfPresenceCS.PhysicalResource.Location[0].ID = addressCS.ID

	// we require also at least one resource we will add a gx:AvailabilityZone which requires an address
	pointOfPresenceCS.AggregationOfResources = make([]gxTypes.ResourceInterface, 1)

	availabilityZone := gxTypes.AvailabilityZone{
		Resource: gxTypes.Resource{GaiaXEntity: gxTypes.GaiaXEntity{CredentialSubjectShape: vc.CredentialSubjectShape{Type: "gx:AvailabilityZone"}}},
		Address: gxTypes.Address{
			CredentialSubjectShape: vc.CredentialSubjectShape{ID: addressCS.ID, Type: "gx:Address"},
		},
	}

	pointOfPresenceCS.AggregationOfResources[0] = availabilityZone

	// normally we would require the Participants from above but the main branch is ahead in ontology and needs an InterconnectedParticipant
	pointOfPresenceCS.InterconnectedParticipants = []gxTypes.LegalPerson{{Participant: gxTypes.Participant{GaiaXEntity: gxTypes.GaiaXEntity{CredentialSubjectShape: vc.CredentialSubjectShape{ID: companyCS.ID, Type: "gx:LegalPerson"}}}}}

	pointOfPresenceCS.ID = pointOfPresenceVC.ID + "#cs"

	err = pointOfPresenceVC.AddToCredentialSubject(pointOfPresenceCS)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(pointOfPresenceVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(pointOfPresenceVC.GetOriginalJWS())

	datacenterVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"DataCenter"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:Datacenter"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)

	datacenterCS := gxTypes.Datacenter{
		PhysicalResource: gxTypes.PhysicalResource{
			// same as before we will declare the DataCenter is owned by the same company
			OwnedBy: []gxTypes.LegalPerson{{Participant: gxTypes.Participant{GaiaXEntity: gxTypes.GaiaXEntity{CredentialSubjectShape: vc.CredentialSubjectShape{ID: companyCS.ID, Type: "gx:LegalPerson"}}}}}, //should be ISP
			// again one empty gx:Address to fill later
			Location: make([]gxTypes.Address, 1),
		},
	}

	// filling the address
	datacenterCS.Location[0].Type = "gx:Address"
	datacenterCS.Location[0].ID = addressCS.ID

	// we also declare the data center is maintained by the same company that owns it
	datacenterCS.MaintainedBy = datacenterCS.OwnedBy

	// we need again one resource so we add an AvailabilityZone, technically we could have added a VC with gx:Resource
	// gx:AvailabilityZone and add here only the ID of the Credential Subject
	datacenterCS.AggregationOfResources = []gxTypes.ResourceInterface{availabilityZone}

	datacenterCS.ID = datacenterVC.ID + "#cs"

	err = datacenterVC.AddToCredentialSubject(datacenterCS)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(datacenterVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(datacenterVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// The Provider shall explain how information about subcontractors and related Customer Data localization will be
	// communicated.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p126
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P1.2.6
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-subcontractor-details.filter.ts

	// the subcontractor needs two legal documents therefore we will not define them inline instead make a vc
	subContractorLegalDocumentVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"SubContractorLegalDocument"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:LegalDocument"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	subContractorLegalDocument := gxTypes.LegalDocument{
		// vc.WithAnyURI is just a convenience function for @value provided string and @value: xsd:anyURI
		URL: vc.WithAnyURI("https://www.posedio.com/LegalDocumentsSubContractor"),
	}

	subContractorLegalDocument.ID = subContractorLegalDocumentVC.ID + "#cs"

	err = subContractorLegalDocumentVC.AddToCredentialSubject(subContractorLegalDocument)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(subContractorLegalDocumentVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(subContractorLegalDocumentVC.GetOriginalJWS())

	subcontractorVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"Subcontractor"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:SubContractor"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)

	// SubContractor represents a subcontractor with specific legal and communication attributes
	subcontractorCS := gxTypes.SubContractor{
		ApplicableJurisdiction: "AT",
		LegalName:              "Posedio GmbH",
		CommunicationMethods:   make([]gxTypes.LegalDocument, 1),
		InformationDocuments:   make([]gxTypes.LegalDocument, 1),
	}

	subcontractorCS.ID = subcontractorVC.ID + "#cs"
	subcontractorCS.CommunicationMethods[0].ID = subContractorLegalDocument.ID
	subcontractorCS.InformationDocuments[0].ID = subContractorLegalDocument.ID

	err = subcontractorVC.AddToCredentialSubject(subcontractorCS)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(subcontractorVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(subcontractorVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Customer Data Access Terms legal document
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p521
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P5.2.1
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-customer-data-access-terms.filter.ts

	customerDataAccessTermsVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"CustomerDataAccessTerms"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:CustomerDataAccessTerms"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)

	customerDataAccessTerms := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/privacy"),
	}

	customerDataAccessTerms.ID = customerDataAccessTermsVC.ID + "#cs"

	err = customerDataAccessTermsVC.AddToCredentialSubject(customerDataAccessTerms)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(customerDataAccessTermsVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(customerDataAccessTermsVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// change and configuration management
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p3112
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.12
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-change-and-configuration-management.filter.ts

	ChangeAndConfigurationManagementVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"ChangeAndConfigurationManagement"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:ChangeAndConfigurationManagement"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)

	ChangeAndConfigurationManagement := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/ConfigurationManagement"),
	}
	ChangeAndConfigurationManagement.ID = ChangeAndConfigurationManagementVC.ID + "#cs"

	err = ChangeAndConfigurationManagementVC.AddToCredentialSubject(ChangeAndConfigurationManagement)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(ChangeAndConfigurationManagementVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(ChangeAndConfigurationManagementVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// product security
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p3120
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.20
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-product-security.filter.ts

	ProductSecurityVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"ProductSecurity"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:ProductSecurity"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)

	ProductSecurity := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/ProductSecurity"),
	}
	ProductSecurity.ID = ProductSecurityVC.ID + "#cs"
	err = ProductSecurityVC.AddToCredentialSubject(ProductSecurity)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(ProductSecurityVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(ProductSecurityVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// product security
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p3119
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.19
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-government-investigation-management.filter.ts

	GovernmentInvestigationManagementVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"GovernmentInvestigationManagement"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:GovernmentInvestigationManagement"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)

	GovernmentInvestigationManagement := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/GovernmentInvestigationManagement"),
	}
	GovernmentInvestigationManagement.ID = GovernmentInvestigationManagementVC.ID + "#cs"
	err = GovernmentInvestigationManagementVC.AddToCredentialSubject(GovernmentInvestigationManagement)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(GovernmentInvestigationManagementVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(GovernmentInvestigationManagementVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// User documentation: Provide up-to-date information on the secure configuration and known vulnerabilities of the cloud
	//service for cloud customers.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p3119
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.19
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-government-investigation-management.filter.ts

	UserDocumentationMaintenanceVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"UserDocumentationMaintenance"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:UserDocumentationMaintenance"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)

	UserDocumentationMaintenance := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/UserDocumentationMaintenance"),
	}
	UserDocumentationMaintenance.ID = UserDocumentationMaintenanceVC.ID + "#cs"
	err = UserDocumentationMaintenanceVC.AddToCredentialSubject(UserDocumentationMaintenance)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(UserDocumentationMaintenanceVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(UserDocumentationMaintenanceVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Compliance: Avoid non-compliance with legal, regulatory, self-imposed or contractual information security and
	//compliance requirements.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p3117
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.17
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-compliance-assurance.filter.ts

	ComplianceAssuranceVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"ComplianceAssurance"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:ComplianceAssurance"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	ComplianceAssurance := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/ComplianceAssurance"),
	}
	ComplianceAssurance.ID = ComplianceAssuranceVC.ID + "#cs"
	err = ComplianceAssuranceVC.AddToCredentialSubject(ComplianceAssurance)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(ComplianceAssuranceVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(ComplianceAssuranceVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Business Continuity: Plan, implement, maintain and test procedures and measures for business continuity and emergency
	//management.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p3116
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.16
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-business-continuity-measures.filter.ts

	BusinessContinuityMeasuresVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"BusinessContinuityMeasures"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:BusinessContinuityMeasures"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)

	BusinessContinuityMeasures := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/BusinessContinuityMeasures"),
	}
	BusinessContinuityMeasures.ID = BusinessContinuityMeasuresVC.ID + "#cs"
	err = BusinessContinuityMeasuresVC.AddToCredentialSubject(BusinessContinuityMeasures)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(BusinessContinuityMeasuresVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(BusinessContinuityMeasuresVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Business Continuity: Plan, implement, maintain and test procedures and measures for business continuity and emergency
	//management.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p3115
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.15
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-security-incident-management.filter.ts

	SecurityIncidentManagementVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"SecurityIncidentManagement"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:SecurityIncidentManagement"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)
	SecurityIncidentManagement := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/SecurityIncidentManagement"),
	}
	SecurityIncidentManagement.ID = SecurityIncidentManagementVC.ID + "#cs"
	err = SecurityIncidentManagementVC.AddToCredentialSubject(SecurityIncidentManagement)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(SecurityIncidentManagementVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(SecurityIncidentManagementVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Procurement Management: Ensure the protection of information that suppliers of the CSP can access and monitor the
	//agreed services and security requirements.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p3114
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.14
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-procurement-management-security.filter.ts

	ProcurementManagementSecurityVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"ProcurementManagementSecurity"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:ProcurementManagementSecurity"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)
	ProcurementManagementSecurity := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/ProcurementManagementSecurity"),
	}
	ProcurementManagementSecurity.ID = ProcurementManagementSecurityVC.ID + "#cs"
	err = ProcurementManagementSecurityVC.AddToCredentialSubject(ProcurementManagementSecurity)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(ProcurementManagementSecurityVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(ProcurementManagementSecurityVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Development of Information systems: Ensure information security in the development cycle of information systems.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p3113
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.13
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-development-cycle-security.filter.ts

	DevelopmentCycleSecurityVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"DevelopmentCycleSecurity"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:DevelopmentCycleSecurity"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)
	DevelopmentCycleSecurity := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/DevelopmentCycleSecurity"),
	}
	DevelopmentCycleSecurity.ID = DevelopmentCycleSecurityVC.ID + "#cs"

	err = DevelopmentCycleSecurityVC.AddToCredentialSubject(DevelopmentCycleSecurity)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(DevelopmentCycleSecurityVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(DevelopmentCycleSecurityVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// The Provider shall implement practices for facilitating the switching of Providers and the porting of Customer Data in
	//a structured, commonly used and machine-readable format including open standard formats where required or requested by
	//the Customer.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p411
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P4.1.1
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-development-cycle-security.filter.ts

	dataPortabilityVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"DataPortability"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:DataPortability"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext(),
	)
	dataPortability := gxTypes.DataPortability{
		Formats:        []string{"swagger"},
		Documentations: []vc.URL{vc.WithAnyURI("https://www.posedio.com/docs")},
		LegalDocument: gxTypes.LegalDocument{
			URL: vc.WithAnyURI("https://www.posedio.com/DataPortability"),
		},
		Means:             []string{"Means used to transfer the customer's stored data to another provider. String"},
		Pricing:           vc.WithAnyURI("https://www.posedio.com/pricing"),
		Resource:          pointOfPresenceCS.ID,
		DeletionMethods:   []string{"none"},
		DeletionTimeframe: "years",
	}
	dataPortability.ID = dataPortabilityVC.ID + "#cs"
	err = dataPortabilityVC.AddToCredentialSubject(dataPortability)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(dataPortabilityVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(dataPortabilityVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Physical Security: Prevent unauthorised physical access and protect against theft, damage, loss and outage of
	//operations.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p316
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.6
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-physical-security.filter.ts

	PhysicalSecurityVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"PhysicalSecurity"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:PhysicalSecurity"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	PhysicalSecurity := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/PhysicalSecurity"),
	}
	PhysicalSecurity.ID = PhysicalSecurityVC.ID + "#cs"
	err = PhysicalSecurityVC.AddToCredentialSubject(PhysicalSecurity)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(PhysicalSecurityVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(PhysicalSecurityVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Information Security Policies: Provide a global information security policy, derived into policies and procedures
	//regarding security requirements and to support business requirements.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p312
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.2
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-information-security-policies.filter.ts

	InformationSecurityPoliciesVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"InformationSecurityPolicies"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:InformationSecurityPolicies"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	InformationSecurityPolicies := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/InformationSecurityPolicies"),
	}
	InformationSecurityPolicies.ID = InformationSecurityPoliciesVC.ID + "#cs"
	err = InformationSecurityPoliciesVC.AddToCredentialSubject(InformationSecurityPolicies)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(InformationSecurityPoliciesVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(InformationSecurityPoliciesVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Risk Management: Ensure that risks related to information security are properly identified, assessed, and treated, and
	//that the residual risk is acceptable to the CSP.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p313
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.3
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-information-security-risk-management.filter.ts

	InformationSecurityRiskManagementVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"InformationSecurityRiskManagement"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:InformationSecurityRiskManagement"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())
	InformationSecurityRiskManagement := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/InformationSecurityRiskManagement"),
	}
	InformationSecurityRiskManagement.ID = InformationSecurityRiskManagementVC.ID + "#cs"
	err = InformationSecurityRiskManagementVC.AddToCredentialSubject(InformationSecurityRiskManagement)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(InformationSecurityRiskManagementVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(InformationSecurityRiskManagementVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Human Resources: Ensure that employees understand their responsibilities, are aware of their responsibilities with
	//regard to information security, and that the organisation’s assets are protected in the event of changes in
	//responsibilities or termination.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p314
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.4
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-employee-responsibilities.filter.ts

	EmployeeResponsibilitiesVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"EmployeeResponsibilities"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:EmployeeResponsibilities"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())
	EmployeeResponsibilities := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/EmployeeResponsibilities"),
	}
	EmployeeResponsibilities.ID = EmployeeResponsibilitiesVC.ID + "#cs"

	err = EmployeeResponsibilitiesVC.AddToCredentialSubject(EmployeeResponsibilities)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(EmployeeResponsibilitiesVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(EmployeeResponsibilitiesVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Organization of information security: Plan, implement, maintain and continuously improve the information security
	//framework within the organisation.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p311
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.1
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-information-security-organization.filter.ts

	InformationSecurityOrganizationVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"InformationSecurityOrganization"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:InformationSecurityOrganization"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	InformationSecurityOrganization := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/InformationSecurityOrganization"),
	}
	InformationSecurityOrganization.ID = InformationSecurityOrganizationVC.ID + "#cs"
	err = InformationSecurityOrganizationVC.AddToCredentialSubject(InformationSecurityOrganization)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(InformationSecurityOrganizationVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(InformationSecurityOrganizationVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Asset Management: Identify the organisation’s own assets and ensure an appropriate level of protection throughout
	//their lifecycle.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p315
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.5
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-assets-management.filter.ts

	AssetsManagementVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"AssetsManagement"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:AssetsManagement"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	AssetsManagement := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/AssetsManagement"),
	}
	AssetsManagement.ID = AssetsManagementVC.ID + "#cs"
	err = AssetsManagementVC.AddToCredentialSubject(AssetsManagement)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(AssetsManagementVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(AssetsManagementVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// The Provider shall define the audit rights for the Customer.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p227
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P2.2.7
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-customer-auditing-rights.filter.ts

	CustomerAuditingRightsVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"CustomerAuditingRights"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:CustomerAuditingRights"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	CustomerAuditingRights := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/CustomerAuditingRights"),
	}
	CustomerAuditingRights.ID = CustomerAuditingRightsVC.ID + "#cs"
	err = CustomerAuditingRightsVC.AddToCredentialSubject(CustomerAuditingRights)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(CustomerAuditingRightsVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(CustomerAuditingRightsVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Operational Security: Ensure proper and regular operation, including appropriate measures for planning and monitoring
	//capacity, protection against malware, logging and monitoring events, and dealing with vulnerabilities, malfunctions
	//and failures.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p317
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.7
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-operational-security.filter.ts

	OperationalSecurityVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"OperationalSecurity"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:OperationalSecurity"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	OperationalSecurity := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/OperationalSecurity"),
	}
	OperationalSecurity.ID = OperationalSecurityVC.ID + "#cs"
	err = OperationalSecurityVC.AddToCredentialSubject(OperationalSecurity)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(OperationalSecurityVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(OperationalSecurityVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// The Provider shall be ultimately bound to instructions of the Customer.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p221
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P2.2.1
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-customer-instructions.filter.ts

	customerInstructionsVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"customerInstructions"),
		vc.WithValidFromNow(),
		//vc.WithAdditionalTypes("gx:CustomerInstructions"), will be defined in the credential subject to allow for another type CS of legal person
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	ciTM := gxTypes.LegalDocument{
		URL:                   vc.WithAnyURI("https://www.posedio.com/CustomerInstructionsTermsAndMeans"),
		GoverningLawCountries: []string{"AT"},
		InvolvedParties:       make([]gxTypes.LegalPerson, 1),
	}
	ciTM.ID = customerInstructionsVC.ID + "#CIcs"
	ciTM.InvolvedParties[0].ID = companyCS.ID
	ciTM.InvolvedParties[0].Type = "gx:LegalPerson"
	ciTM.Type = "gx:LegalDocument"

	customerInstructions := gxTypes.CustomerInstructions{}
	customerInstructions.Terms = make([]gxTypes.LegalDocument, 1)
	customerInstructions.Terms[0].ID = ciTM.ID
	customerInstructions.Means = make([]gxTypes.LegalDocument, 1)
	customerInstructions.Means[0].ID = ciTM.ID
	customerInstructions.Type = "gx:CustomerInstructions"

	customerInstructions.ID = customerInstructionsVC.ID + "#cs"
	err = customerInstructionsVC.AddToCredentialSubject(customerInstructions)
	if err != nil {
		t.Fatal(err)
	}

	err = customerInstructionsVC.AddToCredentialSubject(ciTM)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(customerInstructionsVC)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(customerInstructionsVC)

	vp.AddEnvelopedVC(customerInstructionsVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// Identity, Authentication and access control management: Limit access to information and information processing
	//facilities.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p318
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P3.1.8
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-access-control-management.filter.ts

	AccessControlManagementVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"AccessControlManagement"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:AccessControlManagement"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())
	AccessControlManagement := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/AccessControlManagement"),
	}
	AccessControlManagement.ID = AccessControlManagementVC.ID + "#cs"
	err = AccessControlManagementVC.AddToCredentialSubject(AccessControlManagement)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(AccessControlManagementVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(AccessControlManagementVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// The Provider shall define the roles and responsibilities of each party.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p212
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P2.1.2
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-role-and-responsibilities.filter.ts

	RoleAndResponsibilitiesVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"RoleAndResponsibilities"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:RoleAndResponsibilities"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	RoleAndResponsibilities := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/RoleAndResponsibilities"),
	}
	RoleAndResponsibilities.ID = RoleAndResponsibilitiesVC.ID + "#cs"
	err = RoleAndResponsibilitiesVC.AddToCredentialSubject(RoleAndResponsibilities)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(RoleAndResponsibilitiesVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(RoleAndResponsibilitiesVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// The Provider shall include in the contract the contact details where Customer may address any queries regarding the
	//Service Offering and the contract.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p128
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P1.2.8
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-provider-contact-information.filter.ts

	providerContactInformationVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"ProviderContactInformation"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:ProviderContactInformation"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	providerContactInformation := gxTypes.ContactInformation{
		URL: vc.WithAnyURI("https://www.posedio.com/contact"),
	}
	providerContactInformation.PostalAddress.ID = addressCS.ID
	providerContactInformation.ID = providerContactInformationVC.ID + "#cs"
	err = providerContactInformationVC.AddToCredentialSubject(providerContactInformation)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(providerContactInformationVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(providerContactInformationVC.GetOriginalJWS())

	// ___________________________________ criteria ___________________________________
	// The Provider shall ensure there are provisions governing changes, regardless of their kind.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p123
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P1.2.3
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-documented-change-procedures.filter.ts

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

	// ___________________________________ criteria ___________________________________
	// The Provider shall ensure there are provisions governing the rights of the parties to use the service and any Customer
	//Data therein.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p122
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P1.2.2
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-data-usage-rights-for-parties.filter.ts

	LegallyBindingActVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"LegallyBindingAct"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:LegallyBindingAct"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	LegallyBindingAct := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/LegallyBindingAct"),
	}
	LegallyBindingAct.ID = LegallyBindingActVC.ID + "#cs"
	err = LegallyBindingActVC.AddToCredentialSubject(LegallyBindingAct)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(LegallyBindingActVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(LegallyBindingActVC.GetOriginalJWS())

	CustomerDataProcessingTermsVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"CustomerDataProcessingTerms"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:CustomerDataProcessingTerms"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())
	CustomerDataProcessingTerms := gxTypes.LegalDocument{
		URL: vc.WithAnyURI("https://www.posedio.com/CustomerDataProcessingTerms"),
	}
	CustomerDataProcessingTerms.ID = CustomerDataProcessingTermsVC.ID + "#cs"
	err = CustomerDataProcessingTermsVC.AddToCredentialSubject(CustomerDataProcessingTerms)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(CustomerDataProcessingTermsVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(CustomerDataProcessingTermsVC.GetOriginalJWS())

	// https://did.dumss.me/CustomerDataAccessTerms#cs needed but already defined above

	// ___________________________________ criteria ___________________________________
	// The Provider shall clearly define the technical and organizational measures in accordance with the roles and
	//responsibilities of the parties, including an adequate level of detail.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p213
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P2.1.3
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-required-measures.filter.ts

	requiredMeasuresVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"RequiredMeasures"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:RequiredMeasures"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())

	requiredMeasures := gxTypes.Measure{
		LegalDocuments: []gxTypes.LegalDocument{
			{
				URL: vc.WithAnyURI("https://www.posedio.com/LegalDocumentsMeasuremnt"),
			},
		},
		Description: "look at the url",
	}
	requiredMeasures.ID = requiredMeasuresVC.ID + "#cs"
	err = requiredMeasuresVC.AddToCredentialSubject(requiredMeasures)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(requiredMeasuresVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(requiredMeasuresVC.GetOriginalJWS())

	// ___________________________________  not criteria but required ___________________________________
	// a gx:ServiceOffering needs gx:serviceOfferingTermsAndConditions as class gx:TermsAndConditions
	// defined in the SHACL shape

	TermsAndConditionsVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"TermsAndConditions"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:TermsAndConditions"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())
	TermsAndConditionsCS := gxTypes.TermsAndConditions{
		URL:  vc.WithAnyURI("https://www.posedio.com/TermsAndConditions"),
		Hash: "KWySHNUG",
	}
	TermsAndConditionsCS.ID = TermsAndConditionsVC.ID + "#cs"
	err = TermsAndConditionsVC.AddToCredentialSubject(TermsAndConditionsCS)
	if err != nil {
		t.Fatal(err)
	}

	err = connector.SelfSign(TermsAndConditionsVC)
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(TermsAndConditionsVC.GetOriginalJWS())

	// ___________________________________  not criteria but required ___________________________________
	// a gx:ServiceOffering needs gx:dataAccountExport a list of classes gx:DataAccountExport
	// defined in the SHACL shape

	dataAccountExportVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"DataAccountExport"),
		vc.WithValidFromNow(),
		vc.WithAdditionalTypes("gx:DataAccountExport"),
		vc.WithIssuer(issuer),
		vc.WithGaiaXContext())
	dataAccountExportCS := gxTypes.DataAccountExport{
		RequestType: "API",
		AccessType:  "digital",
		FormatType:  "application/json",
	}
	dataAccountExportCS.ID = dataAccountExportVC.ID + "#cs"
	err = dataAccountExportVC.AddToCredentialSubject(dataAccountExportCS)
	if err != nil {
		t.Fatal(err)
	}
	err = connector.SelfSign(dataAccountExportVC)
	if err != nil {
		t.Fatal(err)
	}
	vp.AddEnvelopedVC(dataAccountExportVC.GetOriginalJWS())

	////////////////////
	// Service Offering
	///////////////////
	// ___________________________________ criteria ___________________________________
	// The Provider shall declare the general location of any processing of Customer Data, allowing the Customer to determine
	// the applicable jurisdiction and to comply with Customer’s requirements in the context of its business and operational
	// context.
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/docs/labelling-criteria.md#criterion-p125
	// https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/criteria_cloud_services/#P1.2.5
	// https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/blob/development/src/vp-validation/filter/service-offering-has-a-resource-with-address.filter.ts

	ServiceOfferingVC, _ := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"test"),
		vc.WithIssuer(issuer),
		vc.WithValidFromNow(),
		vc.WithGaiaXContext(),
		vc.WithAdditionalTypes("gx:ServiceOffering"),
	)

	serviceOffering := gxTypes.ServiceOffering{}

	serviceOffering.AddResourceURI(datacenterCS.ID)
	serviceOffering.AddResourceURI(pointOfPresenceCS.ID)
	serviceOffering.CryptographicSecurityStandards = []string{"RFC9142"}
	serviceOffering.AddCustomerInstructionsURI(customerInstructions.ID)
	serviceOffering.AddDataAccountExportURI(dataAccountExportCS.ID)
	serviceOffering.AddDataPortabilityURI(dataPortability.ID)
	serviceOffering.DataProtectionRegime = []string{"LGPD2019"}
	serviceOffering.Keyword = []string{"demo usage"}

	serviceOffering.AddLegalDocumentURI(AccessControlManagement.ID)
	serviceOffering.AddLegalDocumentURI(AssetsManagement.ID)
	serviceOffering.AddLegalDocumentURI(BusinessContinuityMeasures.ID)
	serviceOffering.AddLegalDocumentURI(ChangeAndConfigurationManagement.ID)
	serviceOffering.AddLegalDocumentURI(ComplianceAssurance.ID)
	serviceOffering.AddLegalDocumentURI(CustomerAuditingRights.ID)
	serviceOffering.AddLegalDocumentURI(customerDataAccessTerms.ID)
	serviceOffering.AddLegalDocumentURI(CustomerDataProcessingTerms.ID)
	serviceOffering.AddLegalDocumentURI(DevelopmentCycleSecurity.ID)
	serviceOffering.AddLegalDocumentURI(DocumentChangeProcedures.ID)
	serviceOffering.AddLegalDocumentURI(EmployeeResponsibilities.ID)
	serviceOffering.AddLegalDocumentURI(GovernmentInvestigationManagement.ID)
	serviceOffering.AddLegalDocumentURI(InformationSecurityOrganization.ID)
	serviceOffering.AddLegalDocumentURI(InformationSecurityPolicies.ID)
	serviceOffering.AddLegalDocumentURI(InformationSecurityRiskManagement.ID)
	serviceOffering.AddLegalDocumentURI(LegallyBindingAct.ID)
	serviceOffering.AddLegalDocumentURI(OperationalSecurity.ID)
	serviceOffering.AddLegalDocumentURI(PhysicalSecurity.ID)
	serviceOffering.AddLegalDocumentURI(ProcurementManagementSecurity.ID)
	serviceOffering.AddLegalDocumentURI(ProductSecurity.ID)
	serviceOffering.AddLegalDocumentURI(RoleAndResponsibilities.ID)
	serviceOffering.AddLegalDocumentURI(SecurityIncidentManagement.ID)
	serviceOffering.AddLegalDocumentURI(UserDocumentationMaintenance.ID)

	serviceOffering.ProvidedBy.ID = companyCS.ID
	serviceOffering.ProviderContactInformation.ID = providerContactInformation.ID
	serviceOffering.ProvisionType = "public"
	serviceOffering.AddRequiredMeasuresURI(requiredMeasures.ID)
	serviceOffering.AddServiceOfferingTermsAndConditionsURI(TermsAndConditionsCS.ID)
	serviceOffering.ServiceScope = "EuPG"
	serviceOffering.AddSubContractorURI(subcontractorCS.ID)

	err = ServiceOfferingVC.AddToCredentialSubject(serviceOffering)
	if err != nil {
		t.Fatal(err)
	}

	ServiceOfferingVC.ID = idprefix + "offeringVC"

	ServiceOfferingVC.ValidFrom = time.Now()

	err = connector.SelfSign(ServiceOfferingVC)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(ServiceOfferingVC)

	vp.AddEnvelopedVC(ServiceOfferingVC.GetOriginalJWS())

	//// ------------------- ////
	// show verifiable presentation
	t.Log(vp)

	offering, _, err := connector.SignServiceOffering(compliance.ServiceOfferingComplianceOptions{ServiceOfferingVP: vp, ServiceOfferingLabelLevel: compliance.Level0, Id: idprefix + "complianceCredential"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(offering)

	vp.AddEnvelopedVC(offering.GetOriginalJWS())

	validFor := offering.ValidUntil.Sub(time.Now())

	err = connector.SelfSignPresentation(vp, validFor)
	if err != nil {
		t.Fatal(err)
	}

	vpfromjwt, err := vc.VPFROMJWT(vp.GetOriginalJWS())
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, vp.String(), vpfromjwt.String())

	// decode the verifiable presentation (only copy of it)
	credentials, err := vp.DecodeEnvelopedCredentials()
	if err != nil {
		t.Fatal(err)
	}

	// optional storage of the vc
	store := vc.NewStore()
	for _, v := range credentials {
		err := store.Create(v)
		if err != nil {
			t.Fatal(err)
		}
	}

	err = store.ToFile("test.json", nil)
	if err != nil {
		t.Fatal(err)
	}

	// get vc from storage
	newStore, err := vc.NewStoreFromFile("test.json", nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(newStore.GetAllIndex())

}
