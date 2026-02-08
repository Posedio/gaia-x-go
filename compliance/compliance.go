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
	"net/http"
	"strings"
	"time"

	"github.com/Posedio/gaia-x-go/signer"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/Posedio/gaia-x-go/did"

	vcTypes "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type Compliance interface {
	signer.Signer
	SignLegalRegistrationNumber(options LegalRegistrationNumberOptions) (*vcTypes.VerifiableCredential, error)
	SignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error)
	GaiaXSignParticipant(options ParticipantComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error)
	SelfSignSignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error)
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
	Compliance ServiceUrl
}

type NotaryURL string

const (
	AireV1Notary NotaryURL = "https://gx-notary.airenetworks.es/v1/"
	//ArsysV1Notary    NotaryURL = "https://gx-notary.arsys.es/v1/"
	ArubaV1Notary    NotaryURL = "https://gx-notary.aruba.it/v1/"
	TSystemV1Notary  NotaryURL = "https://gx-notary.gxdch.dih.telekom.com/v1/"
	DeltaDaoV1Notary NotaryURL = "https://www.delta-dao.com/notary/v1/"
	OVHV1Notary      NotaryURL = "https://notary.gxdch.gaiax.ovh/v1/"
	NeustaV1Notary   NotaryURL = "https://aerospace-digital-exchange.eu/notary/v1/"
	ProximusV1Notary NotaryURL = "https://gx-notary.gxdch.proximus.eu/v1/"
	PfalzkomV1Notary NotaryURL = "https://trust-anker.pfalzkom-gxdch.de/v1/"
	CISPEV1Notary    NotaryURL = "https://notary.cispe.gxdch.clouddataengine.io/v1/"
	CISPEV2Notary    NotaryURL = "https://notary.cispe.gxdch.clouddataengine.io/v2/"
	//ArsysV2Notary    NotaryURL = "https://gx-notary.arsys.es/v2/"
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

func (su ServiceUrl) CredentialOfferUrl() ServiceUrl {
	return su
}

func (su ServiceUrl) StatusURL() string {
	sURL := string(su)
	if strings.Contains(sURL, "api") {
		sURL = strings.Replace(sURL, "api", "", 1)
	}
	if strings.Contains(sURL, "/credential-offers") {
		sURL = strings.Replace(sURL, "/credential-offers", "", 1)
	}
	if strings.Contains(sURL, "/credential-offer") {
		sURL = strings.Replace(sURL, "/credential-offer", "", 1)
	}
	return sURL
}

const (
	MainBranch        ServiceUrl = "https://compliance.lab.gaia-x.eu/main/api/credential-offers"
	DevelopmentBranch ServiceUrl = "https://compliance.lab.gaia-x.eu/development/api/credential-offers"
	V1Branch          ServiceUrl = "https://compliance.lab.gaia-x.eu/v1/api/credential-offers"
	V1Staging         ServiceUrl = "https://compliance.lab.gaia-x.eu/v1-staging/api/credential-offers"
	V2Staging         ServiceUrl = "https://compliance.lab.gaia-x.eu/main/api/credential-offers"
	V2                ServiceUrl = "https://compliance.lab.gaia-x.eu/v2/api/credential-offers"
	Development       ServiceUrl = "https://compliance.lab.gaia-x.eu/development/api/credential-offers"
	AireV1            ServiceUrl = "https://gx-compliance.airenetworks.es/v1/credential-offer"
	//ArsysV1           ServiceUrl = "https://gx-compliance.arsys.es/v1/credential-offer"
	ArubaV1    ServiceUrl = "https://gx-compliance.aruba.it/v1/credential-offer"
	TSystemsV1 ServiceUrl = "https://gx-compliance.gxdch.dih.telekom.com/v1/credential-offer"
	DeltaDAOV1 ServiceUrl = "https://www.delta-dao.com/compliance/v1/credential-offer"
	OVHV1      ServiceUrl = "https://compliance.gxdch.gaiax.ovh/v1/credential-offer"
	NeustaV1   ServiceUrl = "https://aerospace-digital-exchange.eu/compliance/v1/credential-offer"
	ProximusV1 ServiceUrl = "https://gx-compliance.gxdch.proximus.eu/v1/credential-offer"
	PfalzKomV1 ServiceUrl = "https://compliance.pfalzkom-gxdch.de/v1/credential-offer"
	CISPEV1    ServiceUrl = "https://compliance.cispe.gxdch.clouddataengine.io/v1/credential-offer"
	CISPEV2    ServiceUrl = "https://compliance.cispe.gxdch.clouddataengine.io/v2/api/credential-offers"
	//ArsysV2           ServiceUrl = "https://gx-compliance.arsys.es/v2/api/credential-offers"
	TSystemsV2 ServiceUrl = "https://gx-compliance.gxdch.dih.telekom.com/v2/api/credential-offers"
	DeltaDaoV2 ServiceUrl = "https://www.delta-dao.com/compliance/v2/api/credential-offers"
	NeustaV2   ServiceUrl = "https://aerospace-digital-exchange.eu/compliance/v2/api/credential-offers"
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
	AireRegistryV1 RegistryUrl = "https://gx-registry.airenetworks.es/v1/"
	//ArsysRegistryV1    RegistryUrl = "https://gx-registry.arsys.es/v1/"
	ArubaRegistryV1    RegistryUrl = "https://gx-registry.aruba.it/v1/"
	TSystemsRegistryV1 RegistryUrl = "https://gx-registry.gxdch.dih.telekom.com/v1/"
	DeltaDaoRegistryV1 RegistryUrl = "https://www.delta-dao.com/registry/v1/"
	OVHRegistryV1      RegistryUrl = "https://registry.gxdch.gaiax.ovh/v1/"
	NeustaRegistryV1   RegistryUrl = "https://aerospace-digital-exchange.eu/registry/v1/"
	ProximusRegistryV1 RegistryUrl = "https://gx-registry.gxdch.proximus.eu/v1/"
	PfalzkomRegistryV1 RegistryUrl = "https://portal.pfalzkom-gxdch.de/v1/"
	CISPERegistryV1    RegistryUrl = "https://registry.cispe.gxdch.clouddataengine.io/v1/"
	CISPERegistryV2    RegistryUrl = "https://registry.cispe.gxdch.clouddataengine.io/v2/"
	RegistryV1         RegistryUrl = "https://registry.lab.gaia-x.eu/v1/"
	//ArsysRegistryV2    RegistryUrl = "https://gx-registry.arsys.es/v2/"
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

// IssuerSetting
// Deprecated: will be removed with the next major release and replaced by signer.IssuerSetting
type IssuerSetting struct {
	Key                jwk.Key
	Alg                jwa.SignatureAlgorithm
	Issuer             string
	VerificationMethod string
}

type options struct {
	retryClient *http.Client
}

// option for future usage
type option struct {
	f func(option *options) error
}

func (so *option) apply(option *options) error {
	return so.f(option)
}

func CustomRetryClient(client *http.Client) option {
	return option{f: func(option *options) error {
		option.retryClient = client
		return nil
	}}
}

// NewComplianceConnectorV3 drops support for Tagus and only supports Loire
func NewComplianceConnectorV3(clearingHouse Endpoints, version string, sign signer.Signer, opts ...option) (Compliance, error) {
	opt := &options{}
	for _, o := range opts {
		if err := o.apply(opt); err != nil {
			return nil, err
		}
	}

	var hc *http.Client

	if opt.retryClient == nil {
		retryClient := retryablehttp.NewClient()
		retryClient.RetryMax = 2
		retryClient.RetryWaitMin = 10 * time.Second
		retryClient.RetryWaitMax = 60 * time.Second
		retryClient.HTTPClient.Timeout = 90 * time.Second
		retryClient.Logger = nil
		retryClient.CheckRetry = vcTypes.DefaultRetryPolicy
		retryClient.StandardClient()
	} else {
		hc = opt.retryClient
	}

	if version == "24.11" || version == "loire" || version == "Loire" {

		c := &LoireCompliance{
			Signer:    sign,
			signUrl:   clearingHouse.Compliance,
			version:   version,
			notaryURL: clearingHouse.Notary,
			client:    hc,
			validate:  validator.New(),
		}

		err := c.validate.RegisterValidation("validateRegistrationNumberType", ValidateRegistrationNumberType)
		if err != nil {
			return nil, err
		}

		return c, nil
	}

	return nil, errors.New("not supported version")
}

// NewComplianceConnectorV2
// Deprecated: will be removed with the next major release
func NewComplianceConnectorV2(clearingHouse Endpoints, version string, issuer *IssuerSetting, opts ...option) (Compliance, error) {
	opt := &options{}
	for _, o := range opts {
		if err := o.apply(opt); err != nil {
			return nil, err
		}
	}
	var hc *http.Client

	if opt.retryClient == nil {
		retryClient := retryablehttp.NewClient()
		retryClient.RetryMax = 2
		retryClient.RetryWaitMin = 10 * time.Second
		retryClient.RetryWaitMax = 60 * time.Second
		retryClient.HTTPClient.Timeout = 90 * time.Second
		retryClient.Logger = nil
		retryClient.CheckRetry = vcTypes.DefaultRetryPolicy
		retryClient.StandardClient()
	} else {
		hc = opt.retryClient
	}

	var didResolved *did.DID
	if issuer != nil {
		if issuer.Issuer != "" || issuer.Key != nil || issuer.VerificationMethod != "" {
			var err error
			didResolved, err = did.ResolveDIDWeb(issuer.Issuer)
			if err != nil {
				var err1 error
				didResolved, err1 = did.UniResolverDID(issuer.Issuer)
				if err1 != nil {
					return nil, errors.Join(err, err1)
				}
			}

			err = didResolved.ResolveMethods()
			if err != nil {
				return nil, err
			}

			k, ok := didResolved.Keys[issuer.VerificationMethod]
			if !ok {
				return nil, fmt.Errorf("verification method %v not in the did %v", issuer.VerificationMethod, issuer)
			}

			if issuer.Key != nil {
				verifyKey, err := issuer.Key.PublicKey()
				if err != nil {
					return nil, err
				}
				if !jwk.Equal(verifyKey, k.JWK) {
					return nil, fmt.Errorf("public key from key does not match public key of did")
				}
			}
		}
	}

	if version == "22.10" || version == "tagus" || version == "Tagus" {

		c := &TagusCompliance{
			signUrl:   clearingHouse.Compliance,
			version:   version,
			issuer:    issuer,
			notaryURL: clearingHouse.Notary,
			client:    hc,
			did:       didResolved,
			validate:  validator.New(),
		}

		err := c.validate.RegisterValidation("validateRegistrationNumberType", ValidateRegistrationNumberType)
		if err != nil {
			return nil, err
		}

		return c, nil
	} else if version == "24.11" || version == "loire" || version == "Loire" {

		c := &LoireCompliance{
			Signer: &signer.JWTSigner{
				Client: hc,
				Issuer: &signer.IssuerSetting{
					Key:                issuer.Key,
					Alg:                issuer.Alg,
					Issuer:             issuer.Issuer,
					VerificationMethod: issuer.VerificationMethod,
				},
			},
			signUrl:   clearingHouse.Compliance,
			version:   version,
			issuer:    issuer,
			notaryURL: clearingHouse.Notary,
			client:    hc,
			//did:       didResolved,
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

// NewComplianceConnector
// Deprecated: will be removed with the next major release
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
		iss := &IssuerSetting{
			Key:                key,
			VerificationMethod: verificationMethod,
			Issuer:             issuer,
			Alg:                jwa.PS256(),
		}
		c := &TagusCompliance{
			signUrl:   signUrl,
			version:   version,
			issuer:    iss,
			notaryURL: notaryUrl,
			client:    hc,
			did:       didResolved,
			validate:  validator.New(),
		}

		err := c.validate.RegisterValidation("validateRegistrationNumberType", ValidateRegistrationNumberType)
		if err != nil {
			return nil, err
		}

		return c, nil
	} else if version == "24.11" || version == "loire" || version == "Loire" {
		iss := &IssuerSetting{
			Key:                key,
			VerificationMethod: verificationMethod,
			Issuer:             issuer,
			Alg:                jwa.PS256(),
		}
		c := &LoireCompliance{
			Signer: &signer.JWTSigner{
				Client: hc,
				Issuer: &signer.IssuerSetting{
					Key:                iss.Key,
					Alg:                iss.Alg,
					Issuer:             iss.Issuer,
					VerificationMethod: iss.VerificationMethod,
				},
			},
			signUrl:   signUrl,
			version:   version,
			issuer:    iss,
			notaryURL: notaryUrl,
			client:    hc,
			validate:  validator.New(),
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
	ValidFor                     time.Duration
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
	lrn, k := pco.participantVC.CredentialSubject.CredentialSubject[0]["gx:legalRegistrationNumber"].(map[string]interface{}) //tagus
	if !k {
		lrn, k = pco.participantVC.CredentialSubject.CredentialSubject[0]["gx:registrationNumber"].(map[string]interface{}) //loire
		if !k {
			return errors.New("legal registration number not present")
		}
	}
	if id, ok := lrn["id"].(string); ok {
		if id != pco.LegalRegistrationNumberVC.ID { //tagus
			if id != pco.LegalRegistrationNumberVC.ID+"#CS" { //loire
				return errors.New("legal registration number id does not match")
			}
		}
	} else {
		return errors.New("legal registration number id missing")
	}

	return nil
}

type ParticipantOptions interface {
	BuildParticipantVC(id string) (*vcTypes.VerifiableCredential, error)
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
