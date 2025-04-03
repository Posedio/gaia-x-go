/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package compliance

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Posedio/gaia-x-go/did"

	vcTypes "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwk"
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
	AireV1Notary     RegistrationNumberUrl = "https://gx-notary.airenetworks.es/v1/registrationNumberVC"
	ArsysV1Notary    RegistrationNumberUrl = "https://gx-notary.arsys.es/v1/registrationNumberVC"
	ArubaV1Notary    RegistrationNumberUrl = "https://gx-notary.aruba.it/v1/registrationNumberVC"
	TSystemV1Notary  RegistrationNumberUrl = "https://gx-notary.gxdch.dih.telekom.com/v1/registrationNumberVC"
	DeltaDaoV1Notary RegistrationNumberUrl = "https://www.delta-dao.com/notary/v1/registrationNumberVC"
	OVHV1Notary      RegistrationNumberUrl = "https://notary.gxdch.gaiax.ovh/v1/registrationNumberVC"
	NeustaV1Notary   RegistrationNumberUrl = "https://aerospace-digital-exchange.eu/notary/v1/registrationNumberVC"
	ProximusV1Notary RegistrationNumberUrl = "https://gx-notary.gxdch.proximus.eu/v1/registrationNumberVC"
	PfalzkomV1Notary RegistrationNumberUrl = "https://trust-anker.pfalzkom-gxdch.de/v1/registrationNumberVC"
	CISPEV1Notary    RegistrationNumberUrl = "https://notary.cispe.gxdch.clouddataengine.io/v1/registrationNumberVC"
	ArsysV2Notary    RegistrationNumberUrl = "https://gx-notary.arsys.es/v2/registration-numbers"
	TSystemV2Notary  RegistrationNumberUrl = "https://gx-notary.gxdch.dih.telekom.com/v2/registration-numbers"
	DeltaDaoV2Notary RegistrationNumberUrl = "https://www.delta-dao.com/notary/v2/registration-numbers"
	NeustaV2Notary   RegistrationNumberUrl = "https://aerospace-digital-exchange.eu/notary/v2/registration-numbers"
	LabV1Notary      RegistrationNumberUrl = "https://registrationnumber.notary.lab.gaia-x.eu/v1/registrationNumberVC"
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

type RegistryUrl string

func (r RegistryUrl) String() string {
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

func NewComplianceConnector(signUrl ServiceUrl, registrationNumberUrl RegistrationNumberUrl, version string, key jwk.Key, issuer string, verificationMethod string) (Compliance, error) {
	if version == "22.10" || version == "tagus" || version == "Tagus" {
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

		c := &TagusCompliance{
			signUrl:               signUrl,
			version:               version,
			key:                   key,
			issuer:                issuer,
			registrationNumberUrl: registrationNumberUrl,
			verificationMethod:    verificationMethod,
			client: &http.Client{
				Timeout: 50 * time.Second,
			},
			did:      didResolved,
			validate: validator.New(),
		}

		err := c.validate.RegisterValidation("validateRegistrationNumberType", ValidateRegistrationNumberType)
		if err != nil {
			return nil, err
		}

		return c, nil
	} else if version == "24.11" || version == "loire" || version == "Loire" {
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

		c := &LoireCompliance{
			signUrl:               signUrl,
			version:               version,
			key:                   key,
			issuer:                issuer,
			registrationNumberUrl: registrationNumberUrl,
			verificationMethod:    verificationMethod,
			client: &http.Client{
				Timeout: 20 * time.Second,
			},
			did:      didResolved,
			validate: validator.New(),
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
	RegistrationNumber string                 `json:"registrationNumber" validate:"required,alphanumunicode"`
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
