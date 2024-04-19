/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package compliance

import (
	"errors"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"time"

	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/did"

	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwk"
	vcTypes "gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/verifiableCredentials"
)

type Compliance interface {
	SelfSign(credential *vcTypes.VerifiableCredential) error
	ReSelfSign(credential *vcTypes.VerifiableCredential) error
	SelfVerify(vc *vcTypes.VerifiableCredential) error
	SignLegalRegistrationNumber(options LegalRegistrationNumberOptions) (*vcTypes.VerifiableCredential, error)
	SignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error)
	GaiaXSignParticipant(options ParticipantComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error)
	SelfSignSignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error)
	SelfSignCredentialSubject(id string, credentialSubject []map[string]interface{}) (*vcTypes.VerifiableCredential, error)
	SignServiceOffering(options ServiceOfferingComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error)
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

type RegistrationNumberUrl string

const (
	ArubaV1Notary   RegistrationNumberUrl = "https://gx-notary.aruba.it/v1/registrationNumberVC"
	TSystemV1Notary RegistrationNumberUrl = "https://gx-notary.gxdch.dih.telekom.com/v1/registrationNumberVC"
	LabV1Notary     RegistrationNumberUrl = "https://registrationnumber.notary.lab.gaia-x.eu/v1/registrationNumberVC"
	AireV1Notary    RegistrationNumberUrl = "https://gx-registry.airenetworks.es/v1/registrationNumberVC"
)

func (rn RegistrationNumberUrl) String() string {
	return string(rn)
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
	AireV1            ServiceUrl = "https://gx-compliance.airenetworks.es/v1/api/credential-offer"
	ArubaV1           ServiceUrl = "https://gx-compliance.aruba.it/v1/api/credential-offer"
	TSystemsV1        ServiceUrl = "https://gx-compliance.gxdch.dih.telekom.com/v1/api/credential-offers"
)

type RegistryUrl string

func (r RegistryUrl) String() string {
	return string(r)
}

const (
	AireRegistryV1     RegistryUrl = "https://gx-registry.airenetworks.es/v1/"
	ArubaRegistryV1    RegistryUrl = "https://gx-registry.aruba.it/v1/"
	TSystemsRegistryV1 RegistryUrl = "https://gx-registry.gxdch.dih.telekom.com/v1/"
	RegistryV1         RegistryUrl = "https://registry.lab.gaia-x.eu/v1/docs"
)

var trustFrameWorkURL = "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#"
var participantURL = "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/participant"

// NewCompliance
// Deprecated: should not be used anymore since normalization is now done in go directly and NewComplianceConnector implements more checks
func NewCompliance(_ string, signUrl ServiceUrl, version string, key jwk.Key, issuer string, verificationMethod string) (Compliance, error) {
	if version == "22.10" {

		retryClient := retryablehttp.NewClient()
		retryClient.RetryMax = 10
		retryClient.RetryWaitMax = 4000 * time.Millisecond
		retryClient.HTTPClient.Timeout = 3500 * time.Millisecond
		retryClient.Logger = nil
		retryClient.CheckRetry = vcTypes.DefaultRetryPolicy

		hc := retryClient.StandardClient()

		c := &Compliance2210{
			signUrl:               signUrl,
			version:               version,
			key:                   key,
			issuer:                issuer,
			registrationNumberUrl: ArubaV1Notary,
			verificationMethod:    verificationMethod,
			client:                hc,
			validate:              validator.New(),
		}
		err := c.validate.RegisterValidation("validateRegistrationNumberType", ValidateRegistrationNumberType)
		if err != nil {
			return nil, err
		}
		return c, nil
	}

	return nil, errors.New("not supported version")
}

func NewComplianceConnector(signUrl ServiceUrl, registrationNumberUrl RegistrationNumberUrl, version string, key jwk.Key, issuer string, verificationMethod string) (Compliance, error) {
	if version == "22.10" {
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

			if key == nil {
				return nil, errors.New("private key has to be set")
			}

			verifyKey, err := key.PublicKey()
			if err != nil {
				return nil, err
			}
			if !jwk.Equal(verifyKey, k.JWK) {
				return nil, fmt.Errorf("public key from key does not match public key of did")
			}
		}

		retryClient := retryablehttp.NewClient()
		retryClient.RetryMax = 10
		retryClient.RetryWaitMax = 4000 * time.Millisecond
		retryClient.HTTPClient.Timeout = 3500 * time.Millisecond
		retryClient.Logger = nil
		retryClient.CheckRetry = vcTypes.DefaultRetryPolicy

		hc := retryClient.StandardClient()

		c := &Compliance2210{
			signUrl:               signUrl,
			version:               version,
			key:                   key,
			issuer:                issuer,
			registrationNumberUrl: registrationNumberUrl,
			verificationMethod:    verificationMethod,
			client:                hc,
			did:                   didResolved,
			validate:              validator.New(),
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
	RegistrationNumber string                 `json:"registrationNumber" validate:"required,alphanumunicode"` //todo add Gaia-X json ontology
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
	vc.Context.Context = append(vc.Context.Context, vcTypes.SecuritySuitesJWS2020, trustFrameWorkURL)
	vc.ID = id
	vc.CredentialSubject.CredentialSubject = pm.ParticipantCredentialSubject
	return vc, nil
}

type ServiceOfferingOptionsAsMap struct {
	CustomContext                    []string
	ServiceOfferingCredentialSubject []map[string]interface{}
}

func (sm ServiceOfferingOptionsAsMap) BuildServiceOfferingVC(id string) (*vcTypes.VerifiableCredential, error) {
	vc := vcTypes.NewEmptyVerifiableCredential()
	vc.Context.Context = append(vc.Context.Context, vcTypes.SecuritySuitesJWS2020, trustFrameWorkURL)
	if sm.CustomContext != nil {
		vc.Context.Context = append(vc.Context.Context, sm.CustomContext...)
	}
	vc.ID = id
	vc.CredentialSubject.CredentialSubject = sm.ServiceOfferingCredentialSubject
	return vc, nil
}
