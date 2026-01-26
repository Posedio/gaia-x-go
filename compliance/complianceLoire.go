/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package compliance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Posedio/gaia-x-go/gxTypes"
	"github.com/Posedio/gaia-x-go/signer"

	vcTypes "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/go-playground/validator/v10"
)

// LoireCompliance is compatibility is checked up to clearinghouse 1.11.1
type LoireCompliance struct {
	signer.Signer
	signUrl   ServiceUrl
	version   string
	issuer    *IssuerSetting
	client    *http.Client
	notaryURL NotaryURL
	validate  *validator.Validate
}

func (c *LoireCompliance) SignLegalRegistrationNumber(options LegalRegistrationNumberOptions) (*vcTypes.VerifiableCredential, error) {
	err := c.validate.Struct(options)
	if err != nil {
		return nil, err
	}

	rURL := c.notaryURL.RegistrationNumberURL()

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
		vcTypes.WithIssuer(c.GetIssuer()),
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

func (c *LoireCompliance) GaiaXSignParticipant(po ParticipantComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error) {
	err := po.BuildParticipantVC()
	if err != nil {
		return nil, nil, err
	}
	po.participantVC.Issuer = c.GetIssuer()
	err = c.SelfSign(po.participantVC)
	if err != nil {
		return nil, nil, err
	}
	vp := vcTypes.NewEmptyVerifiablePresentationV2()
	vp.AddEnvelopedVC(po.participantVC.GetOriginalJWS())
	vp.AddEnvelopedVC(po.LegalRegistrationNumberVC.GetOriginalJWS())
	vp.AddEnvelopedVC(po.TermAndConditionsVC.GetOriginalJWS())

	offering, _, err := c.SignServiceOffering(ServiceOfferingComplianceOptions{
		Id:                        po.Id,
		ServiceOfferingVP:         vp,
		ServiceOfferingLabelLevel: Level0,
	})
	if err != nil {
		return nil, vp, err
	}

	return offering, vp, nil
}

func (c *LoireCompliance) SelfSignSignTermsAndConditions(_ string) (*vcTypes.VerifiableCredential, error) {
	return nil, errors.New("currently not supported by loire")
}

func (c *LoireCompliance) SignServiceOffering(options ServiceOfferingComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return c.SignServiceOfferingWithContext(ctx, options)
}

func (c *LoireCompliance) SignServiceOfferingWithContext(ctx context.Context, options ServiceOfferingComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error) {
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

	err := c.Signer.SelfSignPresentation(vp, options.ValidFor)
	if err != nil {
		return nil, nil, err
	}

	u := c.signUrl.String() + "/" + options.ServiceOfferingLabelLevel.String() + "?vcid=" + url.QueryEscape(options.Id)

	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewBuffer(vp.GetOriginalJWS()))
	if err != nil {
		return nil, vp, err
	}

	req.Header.Set("Content-Type", "application/vp+jwt")

	c.client.Timeout = 120 * time.Second

	do, err := c.client.Do(req)
	if err != nil {
		return nil, vp, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(do.Body)
	all, err := io.ReadAll(do.Body)
	if err != nil {
		return nil, vp, err
	}
	if do.StatusCode != 201 {
		return nil, vp, errors.New(string(all))
	}

	complianceCredential, err := vcTypes.VCFromJWT(all)
	if err != nil {
		return nil, vp, err
	}

	return complianceCredential, vp, nil
}

func (c *LoireCompliance) GetTermsAndConditions(_ RegistryUrl) (string, error) {
	var tc = `The PARTICIPANT signing Gaia-X credentials agrees as follows: - to update its Gaia-X credentials about any changes, be it technical, organizational, or legal - especially but not limited to contractual in regards to the indicated attributes present in the Gaia-X credentials.

		The keypair used to sign Gaia-X credentials will be revoked where Gaia-X Association becomes aware of any inaccurate statements in regards to the claims which result in a non-compliance with the Trust Framework and policy rules defined in the Policy Rules and Labelling Document (PRLD).`

	return tc, errors.New("not online available in loire")
}

type ParticipantV2Options struct {
	LegalPerson gxTypes.LegalPerson
}

func (pm ParticipantV2Options) BuildParticipantVC(id string) (*vcTypes.VerifiableCredential, error) {
	companyVC, _ := vcTypes.NewEmptyVerifiableCredentialV2(
		vcTypes.WithVCID(id),
		vcTypes.WithValidFromNow(),
		vcTypes.WithAdditionalTypes("gx:LegalPerson"),
		vcTypes.WithGaiaXContext(),
	)
	//if pm.LegalPerson.Name != "" {
	companyVC.Context.Context = append(companyVC.Context.Context, vcTypes.Namespace{
		Namespace: "schema",
		URL:       "https://schema.org/",
	})
	//}
	if pm.LegalPerson.ID == "" {
		pm.LegalPerson.ID = companyVC.ID + "#CS"
	}

	err := companyVC.AddToCredentialSubject(pm.LegalPerson)
	if err != nil {
		return nil, err
	}

	return companyVC, nil
}
