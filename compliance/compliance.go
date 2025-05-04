/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package compliance

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"strings"
	"time"

	"github.com/Posedio/gaia-x-go/did"

	vcTypes "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Compliance interface {
	SelfSign(credential *vcTypes.VerifiableCredential) error
	ReSelfSign(credential *vcTypes.VerifiableCredential) error
	SelfSignPresentation(presentation *vcTypes.VerifiablePresentation, validFor time.Duration) error
	SelfVerify(vc *vcTypes.VerifiableCredential) error
	SignLegalRegistrationNumber(options LegalRegistrationNumberOptions) (*vcTypes.VerifiableCredential, error)
	SignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error)
	GaiaXSignParticipant(options ParticipantComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error)
	SelfSignSignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error)
	SelfSignCredentialSubject(id string, credentialSubject []map[string]interface{}) (*vcTypes.VerifiableCredential, error)
	SignServiceOffering(options ServiceOfferingComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error)
	SignServiceOfferingWithContext(ctx context.Context, options ServiceOfferingComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error)
	GetTermsAndConditions(url RegistryUrl) (string, error)
}

// RegistrationNumberType implements the valid typed form https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#gx:legalRegistrationNumber
type RegistrationNumberType string

const (
	VatID   RegistrationNumberType = "gx:vatID"
	LeiCode RegistrationNumberType = "gx:leiCode"
	EUID    RegistrationNumberType = "gx:EUID"
	TaxID   RegistrationNumberType = "gx:taxID"
	EORI    RegistrationNumberType = "gx:EORI"
)

type Endpoints struct {
	Registry   RegistryUrl
	Notary     NotaryURL
	Compliance ComplianceServiceUrl
}

type GXDCH struct {
	V1 Endpoints
	V2 Endpoints
}

var DeltaDAO = GXDCH{
	V1: Endpoints{
		Notary:     DeltaDaoV1Notary,
		Registry:   DeltaDaoRegistryV1,
		Compliance: DeltaDAOV1Compliance,
	},
	V2: Endpoints{
		Notary:     DeltaDaoV2Notary,
		Registry:   DeltaDAORegistryV2,
		Compliance: DeltaDaoV2Compliance,
	},
}

type NotaryURL string

const (
	AireV1Notary     NotaryURL = "https://gx-notary.airenetworks.es/v1/"
	ArsysV1Notary    NotaryURL = "https://gx-notary.arsys.es/v1/"
	ArubaV1Notary    NotaryURL = "https://gx-notary.aruba.it/v1/"
	TSystemV1Notary  NotaryURL = "https://gx-notary.gxdch.dih.telekom.com/v1/"
	DeltaDaoV1Notary NotaryURL = "https://www.delta-dao.com/notary/v1/"
	OVHV1Notary      NotaryURL = "https://notary.gxdch.gaiax.ovh/v1/"
	NeustaV1Notary   NotaryURL = "https://aerospace-digital-exchange.eu/notary/v1/"
	ProximusV1Notary NotaryURL = "https://gx-notary.gxdch.proximus.eu/v1/"
	PfalzkomV1Notary NotaryURL = "https://trust-anker.pfalzkom-gxdch.de/v1/"
	CISPEV1Notary    NotaryURL = "https://notary.cispe.gxdch.clouddataengine.io/v1/"
	ArsysV2Notary    NotaryURL = "https://gx-notary.arsys.es/v2/"
	TSystemV2Notary  NotaryURL = "https://gx-notary.gxdch.dih.telekom.com/v2/"
	DeltaDaoV2Notary NotaryURL = "https://www.delta-dao.com/notary/v2/"
	NeustaV2Notary   NotaryURL = "https://aerospace-digital-exchange.eu/notary/v2/"
	LabV1Notary      NotaryURL = "https://registrationnumber.notary.lab.gaia-x.eu/v1/"
)

func (nc NotaryURL) String() string {
	return string(nc)
}

func (nc NotaryURL) RegistrationNumberURL() string {
	if strings.Contains(string(nc), "v1") {
		return nc.String() + "registrationNumberVC"
	} else if strings.Contains(string(nc), "v2") {
		return nc.String() + "registration-numbers"
	}
	return ""
}

func (nc NotaryURL) StatusURL() string {
	return nc.String()
}

type ServiceUrl string

func (su ServiceUrl) String() string {
	return string(su)
}

const (
	MainBranch        ServiceUrl = "https://compliance.lab.gaia-x.eu/main/api/credential-offers"
	DevelopmentBranch ServiceUrl = "https://compliance.lab.gaia-x.eu/development/api/credential-offers"
	V1Branch          ServiceUrl = "https://compliance.lab.gaia-x.eu/v1/api/credential-offers"
	V1Staging         ServiceUrl = "https://compliance.lab.gaia-x.eu/v1-staging/api/credential-offers"
	V2Staging         ServiceUrl = "https://compliance.lab.gaia-x.eu/main/api/credential-offers"
	AireV1            ServiceUrl = "https://gx-compliance.airenetworks.es/v1/credential-offer"
	ArsysV1           ServiceUrl = "https://gx-compliance.arsys.es/v1/credential-offer"
	ArubaV1           ServiceUrl = "https://gx-compliance.aruba.it/v1/credential-offer"
	TSystemsV1        ServiceUrl = "https://gx-compliance.gxdch.dih.telekom.com/v1/credential-offer"
	DeltaDAOV1        ServiceUrl = "https://www.delta-dao.com/compliance/v1/credential-offer"
	OVHV1             ServiceUrl = "https://compliance.gxdch.gaiax.ovh/v1/credential-offer"
	NeustaV1          ServiceUrl = "https://aerospace-digital-exchange.eu/compliance/v1/credential-offer"
	ProximusV1        ServiceUrl = "https://gx-compliance.gxdch.proximus.eu/v1/credential-offer"
	PfalzKomV1        ServiceUrl = "https://compliance.pfalzkom-gxdch.de/v1/credential-offer"
	CISPEV1           ServiceUrl = "https://compliance.cispe.gxdch.clouddataengine.io/v1/credential-offer"
	ArsysV2           ServiceUrl = "https://gx-compliance.arsys.es/v2/api/credential-offers"
	TSystemsV2        ServiceUrl = "https://gx-compliance.gxdch.dih.telekom.com/v2/api/credential-offers"
	DeltaDaoV2        ServiceUrl = "https://www.delta-dao.com/compliance/v2/api/credential-offers"
	NeustaV2          ServiceUrl = "https://aerospace-digital-exchange.eu/compliance/v2/api/credential-offers"
)

type ComplianceServiceUrl string

func (c ComplianceServiceUrl) CredentialOfferUrl() ServiceUrl {
	return ServiceUrl(string(c) + "/credential-offers")
}

func (c ComplianceServiceUrl) StatusURL() string {
	sURL := string(c)
	if strings.Contains(sURL, "api") {
		sURL = strings.Replace(sURL, "api", "", 1)
	}
	return sURL
}

const (
	MainBranchCompliance        ComplianceServiceUrl = "https://compliance.lab.gaia-x.eu/main/api"
	DevelopmentBranchCompliance ComplianceServiceUrl = "https://compliance.lab.gaia-x.eu/development/api"
	V1BranchCompliance          ComplianceServiceUrl = "https://compliance.lab.gaia-x.eu/v1/api"
	V1StagingCompliance         ComplianceServiceUrl = "https://compliance.lab.gaia-x.eu/v1-staging/api"
	V2StagingCompliance         ComplianceServiceUrl = "https://compliance.lab.gaia-x.eu/main/api"
	AireV1Compliance            ComplianceServiceUrl = "https://gx-compliance.airenetworks.es/v1"
	ArsysV1Compliance           ComplianceServiceUrl = "https://gx-compliance.arsys.es/v1"
	ArubaV1Compliance           ComplianceServiceUrl = "https://gx-compliance.aruba.it/v1"
	TSystemsV1Compliance        ComplianceServiceUrl = "https://gx-compliance.gxdch.dih.telekom.com/v1"
	DeltaDAOV1Compliance        ComplianceServiceUrl = "https://www.delta-dao.com/compliance/v1"
	OVHV1Compliance             ComplianceServiceUrl = "https://compliance.gxdch.gaiax.ovh/v1"
	NeustaV1Compliance          ComplianceServiceUrl = "https://aerospace-digital-exchange.eu/compliance/v1"
	ProximusV1Compliance        ComplianceServiceUrl = "https://gx-compliance.gxdch.proximus.eu/v1"
	PfalzKomV1Compliance        ComplianceServiceUrl = "https://compliance.pfalzkom-gxdch.de/v1"
	CISPEV1Compliance           ComplianceServiceUrl = "https://compliance.cispe.gxdch.clouddataengine.io/v1"
	ArsysV2Compliance           ComplianceServiceUrl = "https://gx-compliance.arsys.es/v2/api"
	TSystemsV2Compliance        ComplianceServiceUrl = "https://gx-compliance.gxdch.dih.telekom.com/v2/api"
	DeltaDaoV2Compliance        ComplianceServiceUrl = "https://www.delta-dao.com/compliance/v2/api"
	NeustaV2Compliance          ComplianceServiceUrl = "https://aerospace-digital-exchange.eu/compliance/v2/api"
)

type RegistryUrl string

func (r RegistryUrl) String() string {
	return string(r)
}

func (r RegistryUrl) TrustedIssuer() string {
	if strings.Contains(string(r), "v1") || strings.Contains(string(r), "v2") {
		url := string(r) + "api/trusted-issuers"

		return url
	}
	return ""
}
func (r RegistryUrl) StatusURL() string {
	return string(r)
}

const (
	AireRegistryV1     RegistryUrl = "https://gx-registry.airenetworks.es/v1/"
	ArsysRegistryV1    RegistryUrl = "https://gx-registry.arsys.es/v1/"
	ArubaRegistryV1    RegistryUrl = "https://gx-registry.aruba.it/v1/"
	TSystemsRegistryV1 RegistryUrl = "https://gx-registry.gxdch.dih.telekom.com/v1/"
	DeltaDaoRegistryV1 RegistryUrl = "https://www.delta-dao.com/registry/v1/"
	OVHRegistryV1      RegistryUrl = "https://registry.gxdch.gaiax.ovh/v1/"
	NeustaRegistryV1   RegistryUrl = "https://aerospace-digital-exchange.eu/registry/v1/"
	ProximusRegistryV1 RegistryUrl = "https://gx-registry.gxdch.proximus.eu/v1/"
	PfalzkomRegistryV1 RegistryUrl = "https://portal.pfalzkom-gxdch.de/v1/"
	CISPERegistryV1    RegistryUrl = "https://registry.cispe.gxdch.clouddataengine.io/v1/"
	RegistryV1         RegistryUrl = "https://registry.lab.gaia-x.eu/v1/"
	ArsysRegistryV2    RegistryUrl = "https://gx-registry.arsys.es/v2/"
	TSystemRegistryV2  RegistryUrl = "https://gx-registry.gxdch.dih.telekom.com/v2/"
	DeltaDAORegistryV2 RegistryUrl = "https://www.delta-dao.com/registry/v2/"
	NeustaRegistryV2   RegistryUrl = "https://aerospace-digital-exchange.eu/registry/v2/"
)

type LabelLevel string

func (l LabelLevel) String() string {
	return string(l)
}

const (
	Level0 LabelLevel = "standard-compliance"
	Level1 LabelLevel = "label-level-1"
	Level2 LabelLevel = "label-level-2"
	Level3 LabelLevel = "label-level-3"
)

var trustFrameWorkURL = "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#"

var trustFrameworkNamespace = vcTypes.Namespace{
	Namespace: "",
	URL:       trustFrameWorkURL,
}

var participantURL = "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/participant"

var participantNamespace = vcTypes.Namespace{
	Namespace: "",
	URL:       participantURL,
}

func NewComplianceConnector(signUrl ServiceUrl, notaryUrl NotaryURL, version string, key jwk.Key, issuer string, verificationMethod string) (Compliance, error) {
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 2
	retryClient.RetryWaitMax = 60 * time.Second
	retryClient.HTTPClient.Timeout = 60 * time.Second
	retryClient.Logger = nil
	retryClient.CheckRetry = vcTypes.DefaultRetryPolicy

	hc := retryClient.StandardClient()

	var didResolved *did.DID
	if issuer != "" || key != nil || verificationMethod != "" {
		var err error
		didResolved, err = did.ResolveDIDWeb(issuer)
		if err != nil {
			var err1 error
			didResolved, err1 = did.UniResolverDID(issuer)
			if err1 != nil {
				return nil, errors.Join(err, err1)
			}
		}

		err = didResolved.ResolveMethods()
		if err != nil {
			return nil, err
		}

		k, ok := didResolved.Keys[verificationMethod]
		if !ok {
			return nil, fmt.Errorf("verification method %v not in the did %v", verificationMethod, issuer)
		}

		if key != nil {
			verifyKey, err := key.PublicKey()
			if err != nil {
				return nil, err
			}
			if !jwk.Equal(verifyKey, k.JWK) {
				return nil, fmt.Errorf("public key from key does not match public key of did")
			}
		}
	}

	if version == "22.10" || version == "tagus" || version == "Tagus" {

		c := &TagusCompliance{
			signUrl:            signUrl,
			version:            version,
			key:                key,
			issuer:             issuer,
			notaryURL:          notaryUrl,
			verificationMethod: verificationMethod,
			client:             hc,
			did:                didResolved,
			validate:           validator.New(),
		}

		err := c.validate.RegisterValidation("validateRegistrationNumberType", ValidateRegistrationNumberType)
		if err != nil {
			return nil, err
		}

		return c, nil
	} else if version == "24.11" || version == "loire" || version == "Loire" {

		c := &LoireCompliance{
			signUrl:            signUrl,
			version:            version,
			key:                key,
			issuer:             issuer,
			notaryURL:          notaryUrl,
			verificationMethod: verificationMethod,
			client:             hc,
			did:                didResolved,
			validate:           validator.New(),
		}

		err := c.validate.RegisterValidation("validateRegistrationNumberType", ValidateRegistrationNumberType)
		if err != nil {
			return nil, err
		}

		return c, nil
	}

	return nil, errors.New("not supported version")
}

type LegalRegistrationNumberOptions struct {
	Id                 string                 `json:"id" validate:"required,uri"`
	RegistrationNumber string                 `json:"registrationNumber" validate:"required"`
	Type               RegistrationNumberType `json:"type" validate:"required,validateRegistrationNumberType"`
}

func ValidateRegistrationNumberType(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	switch s {
	case string(EUID):
		return true
	case string(EORI):
		return true
	case string(TaxID):
		return true
	case string(LeiCode):
		return true
	case string(VatID):
		return true
	default:
		return false
	}

}

type ServiceOfferingComplianceOptions struct {
	Id                           string
	ParticipantComplianceOptions ParticipantComplianceOptions
	ServiceOfferingOptions       ServiceOfferingOptions
	ServiceOfferingVP            *vcTypes.VerifiablePresentation
	ServiceOfferingLabelLevel    LabelLevel
	serviceOfferingVC            *vcTypes.VerifiableCredential
}

func (sco *ServiceOfferingComplianceOptions) BuildVC() error {
	err := sco.ParticipantComplianceOptions.BuildParticipantVC()
	if err != nil {
		return err
	}

	vc, err := sco.ServiceOfferingOptions.BuildServiceOfferingVC(sco.Id)
	if err != nil {
		return err
	}
	sco.serviceOfferingVC = vc

	by, k := sco.serviceOfferingVC.CredentialSubject.CredentialSubject[0]["gx:providedBy"].(map[string]interface{})
	if k {
		if id, ok := by["id"].(string); ok {
			if id != sco.ParticipantComplianceOptions.participantVC.ID {
				return errors.New("provided by id does not match")
			}
		} else {
			return errors.New("provided by id does not match")
		}
	} else {
		return errors.New("provided by id does not match")
	}

	return nil
}

type ServiceOfferingOptions interface {
	BuildServiceOfferingVC(id string) (*vcTypes.VerifiableCredential, error)
}

type ParticipantComplianceOptions struct {
	Id                        string                        `json:"id" validate:"required,uri"` // Id will be the future id of the verifiable credential
	TermAndConditionsVC       *vcTypes.VerifiableCredential `validate:"required"`               // TermAndConditionsVC the pointer to the T&C vc
	LegalRegistrationNumberVC *vcTypes.VerifiableCredential `validate:"required"`               // LegalRegistrationNumberVC pointer to the legal registration number vc
	Participant               ParticipantOptions            `validate:"required"`               // Participant includes the interface to ParticipantOptions, these require that a vc can be built from it
	participantVC             *vcTypes.VerifiableCredential //internal used to store the vc from the BuildParticipantVC function of the ParticipantOptions
}

func (pco *ParticipantComplianceOptions) BuildParticipantVC() error {
	vc, err := pco.Participant.BuildParticipantVC(pco.Id)
	if err != nil {
		return err
	}
	pco.participantVC = vc

	//test on legal registration number
	lrn, k := pco.participantVC.CredentialSubject.CredentialSubject[0]["gx:legalRegistrationNumber"].(map[string]interface{})
	if k {
		if id, ok := lrn["id"].(string); ok {
			if id != pco.LegalRegistrationNumberVC.ID {
				return errors.New("legal registration number id does not match")
			}
		} else {
			return errors.New("legal registration number id missing")
		}
	} else {
		return errors.New("gx:legalRegistrationNumber missing")
	}

	return nil
}

type ParticipantOptions interface {
	BuildParticipantVC(id string) (*vcTypes.VerifiableCredential, error)
}

type ParticipantOptionsAsMap struct {
	ParticipantCredentialSubject []map[string]interface{}
}

func (pm ParticipantOptionsAsMap) BuildParticipantVC(id string) (*vcTypes.VerifiableCredential, error) {
	vc := vcTypes.NewEmptyVerifiableCredential()
	vc.Context.Context = append(vc.Context.Context, vcTypes.SecuritySuitesJWS2020, trustFrameworkNamespace)
	vc.ID = id
	vc.CredentialSubject.CredentialSubject = pm.ParticipantCredentialSubject
	return vc, nil
}

type ServiceOfferingOptionsAsMap struct {
	CustomContext                    []vcTypes.Namespace
	ServiceOfferingCredentialSubject []map[string]interface{}
}

func (sm ServiceOfferingOptionsAsMap) BuildServiceOfferingVC(id string) (*vcTypes.VerifiableCredential, error) {
	vc := vcTypes.NewEmptyVerifiableCredential()
	vc.Context.Context = append(vc.Context.Context, vcTypes.SecuritySuitesJWS2020, trustFrameworkNamespace)
	if sm.CustomContext != nil {
		vc.Context.Context = append(vc.Context.Context, sm.CustomContext...)
	}
	vc.ID = id
	vc.CredentialSubject.CredentialSubject = sm.ServiceOfferingCredentialSubject
	return vc, nil
}
