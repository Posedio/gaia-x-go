/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package compliance

import (
	"bytes"
	"errors"
	"fmt"
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/gxTypes"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/did"
	vcTypes "gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/verifiableCredentials"
)

// LoireCompliance is compatibility is checked up to clearinghouse 1.11.1
type LoireCompliance struct {
	signUrl               ServiceUrl
	version               string
	issuer                string
	verificationMethod    string
	key                   jwk.Key
	client                *http.Client
	did                   *did.DID
	registrationNumberUrl RegistrationNumberUrl
	validate              *validator.Validate
}

// SelfSign adds a crypto proof to the self-description
func (c *LoireCompliance) SelfSign(vc *vcTypes.VerifiableCredential) error {
	_, err := c.SelfSignVC(vc)
	return err
}

func (c *LoireCompliance) ReSelfSign(credential *vcTypes.VerifiableCredential) error {
	credential.Proof = nil
	_, err := c.SelfSignVC(credential)
	return err
}

func (c *LoireCompliance) SelfSignVC(vc *vcTypes.VerifiableCredential) (*vcTypes.VerifiableCredential, error) {
	if vc == nil {
		return nil, errors.New("vc can not be nil")
	}

	headers := jws.NewHeaders()
	err := headers.Set("alg", jwa.PS256)
	if err != nil {
		return nil, err
	}
	err = headers.Set("iss", c.issuer)
	if err != nil {
		return nil, err
	}
	err = headers.Set("kid", c.verificationMethod)
	if err != nil {
		return nil, err
	}
	err = headers.Set("iat", time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	err = headers.Set("exp", time.Now().UnixMilli()+(time.Hour*24*30).Milliseconds())
	if err != nil {
		return nil, err
	}
	err = headers.Set("cty", "vc+ld")
	if err != nil {
		return nil, err
	}
	err = headers.Set("typ", "vc+ld+jwt")
	if err != nil {
		return nil, err
	}

	jsc, err := vc.JSC()
	if err != nil {
		return nil, err
	}

	buf, err := jws.Sign(jsc, jws.WithKey(jwa.PS256, c.key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, err
	}

	err = vc.AddSignature(buf)
	if err != nil {
		return nil, err
	}

	return vc, nil

}

func (c *LoireCompliance) SelfVerify(vc *vcTypes.VerifiableCredential) error {
	return vc.Verify()
}

func (c *LoireCompliance) SignLegalRegistrationNumber(options LegalRegistrationNumberOptions) (*vcTypes.VerifiableCredential, error) {
	err := c.validate.Struct(options)
	if err != nil {
		return nil, err
	}

	rURL := c.registrationNumberUrl.String()

	switch options.Type {
	case VatID:
		rURL += "/vat-id/" + options.RegistrationNumber
	case LeiCode:
		rURL += "/lei-code/" + options.RegistrationNumber
	case EORI:
		rURL += "/eori-" + options.RegistrationNumber
	case TaxID:
		rURL += "/tax-id/" + options.RegistrationNumber
	default:
		return nil, errors.New("not implemented")
	}

	escapedId := url.QueryEscape(options.Id)
	escapedIdCS := url.QueryEscape(options.Id + "#CS")

	rURL += "?vcId=" + escapedId
	rURL += "&subjectId=" + escapedIdCS

	req, err := http.NewRequest("GET", rURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode != 200 {
		errBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("signing was not successful: %v", string(errBody))
	}

	credential, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	cred, err := vcTypes.VCFromJWT(credential)
	if err != nil {
		return nil, err
	}
	return cred, nil
}

func (c *LoireCompliance) SignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error) {
	tcVC, _ := vcTypes.NewEmptyVerifiableCredentialV2(
		vcTypes.WithVCID(id),
		vcTypes.WithValidFromNow(),
		vcTypes.WithAdditionalTypes("gx:Issuer"),
		vcTypes.WithIssuer(c.issuer),
		vcTypes.WithGaiaXContext(),
	)
	/*
		the currents value can be found at https://docs.gaia-x.eu/ontology/development/enums/GaiaXTermsAndConditions/
		the value is the:
		SHA256 check sum of Gaia-X Terms and Conditions: 'The PARTICIPANT signing Gaia-X credentials agrees as follows: - to update its Gaia-X credentials about any changes, be it technical, organizational, or legal - especially but not limited to contractual in regards to the indicated attributes present in the Gaia-X credentials.

		The keypair used to sign Gaia-X credentials will be revoked where Gaia-X Association becomes aware of any inaccurate statements in regards to the claims which result in a non-compliance with the Trust Framework and policy rules defined in the Policy Rules and Labelling Document (PRLD).'
	*/
	tcVCCS := gxTypes.Issuer{
		GaiaxTermsAndConditions: "4bd7554097444c960292b4726c2efa1373485e8a5565d94d41195214c5e0ceb3",
	}

	err := tcVC.AddToCredentialSubject(tcVCCS)
	if err != nil {
		return nil, err
	}

	// we are going to define every credential subject as subset of the id of the vc, since we will only add one credential per VC this is fine,
	// keep in mind if you add multiple ones you have to provide an ID for each.
	tcVCCS.ID = tcVC.ID + "#cs"

	err = c.SelfSign(tcVC)
	if err != nil {
		return nil, err
	}

	return tcVC, nil
}

func (c *LoireCompliance) SelfSignCredentialSubject(id string, credentialSubject []map[string]interface{}) (*vcTypes.VerifiableCredential, error) {
	vc, err := vcTypes.NewEmptyVerifiableCredentialV2(
		vcTypes.WithVCID(id),
		vcTypes.WithValidFromNow(),
		vcTypes.WithIssuer(c.issuer),
		vcTypes.WithGaiaXContext())

	if err != nil {
		return nil, err
	}

	err = vc.AddToCredentialSubject(credentialSubject)
	if err != nil {
		return nil, err
	}

	signedVC, err := c.SelfSignVC(vc)
	if err != nil {
		return nil, err
	}
	return signedVC, nil
}

func (c *LoireCompliance) GaiaXSignParticipant(options ParticipantComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error) {
	return nil, nil, errors.New("currently not supported by loire")

}

func (c *LoireCompliance) SelfSignSignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error) {
	return nil, errors.New("currently not supported by loire")
}

func (c *LoireCompliance) SignServiceOffering(options ServiceOfferingComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error) {
	if options.ServiceOfferingVP == nil {
		return nil, nil, errors.New("ServiceOfferingLoire is required")
	}
	if options.ServiceOfferingLabelLevel == "" {
		return nil, nil, errors.New("ServiceOfferingLabelLevel is required")
	}
	if options.Id == "" {
		return nil, nil, errors.New("id is required")
	}

	vp := options.ServiceOfferingVP

	headers := jws.NewHeaders()

	err := headers.Set("cty", "vp")
	if err != nil {
		return nil, nil, err
	}
	err = headers.Set("typ", "vp+jwt")
	if err != nil {
		return nil, nil, err
	}

	err = headers.Set("alg", jwa.PS256)
	if err != nil {
		return nil, nil, err
	}
	err = headers.Set("iss", c.issuer)
	if err != nil {
		return nil, nil, err
	}

	err = headers.Set("kid", c.verificationMethod)
	if err != nil {
		return nil, nil, err
	}

	vp.Issuer = c.issuer
	vp.ValidFrom = time.Now()

	j, err := vp.ToJson()
	if err != nil {
		return nil, nil, err
	}

	buf, err := jws.Sign(j, jws.WithKey(jwa.PS256, c.key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, nil, err
	}

	u := c.signUrl.String() + "/" + options.ServiceOfferingLabelLevel.String() + "?vcid=" + url.QueryEscape(options.Id)

	req, err := http.NewRequest("POST", u, bytes.NewBuffer(buf))
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Content-Type", "application/vc+ld+json+jwt")

	c.client.Timeout = 60 * time.Second

	do, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer do.Body.Close()
	all, err := io.ReadAll(do.Body)
	if err != nil {
		return nil, nil, err
	}
	if do.StatusCode != 201 {
		return nil, nil, fmt.Errorf(string(all))
	}

	complianceCredential, err := vcTypes.VCFromJWT(all)
	if err != nil {
		return nil, nil, err
	}

	return complianceCredential, vp, nil
}

func (c *LoireCompliance) GetTermsAndConditions(_ RegistryUrl) (string, error) {
	var tc = `The PARTICIPANT signing Gaia-X credentials agrees as follows: - to update its Gaia-X credentials about any changes, be it technical, organizational, or legal - especially but not limited to contractual in regards to the indicated attributes present in the Gaia-X credentials.

		The keypair used to sign Gaia-X credentials will be revoked where Gaia-X Association becomes aware of any inaccurate statements in regards to the claims which result in a non-compliance with the Trust Framework and policy rules defined in the Policy Rules and Labelling Document (PRLD).`

	return tc, errors.New("not online available in loire")
}
