/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Posedio/gaia-x-go/gxTypes"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/Posedio/gaia-x-go/did"
	vcTypes "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type TagusCompliance struct {
	signUrl   ServiceUrl
	version   string
	issuer    *IssuerSetting
	client    *http.Client
	did       *did.DID
	notaryURL NotaryURL
	validate  *validator.Validate
}

// SelfSign adds a crypto proof to the self-description
func (c *TagusCompliance) SelfSign(vc *vcTypes.VerifiableCredential) error {
	//check on valid json and prepare for proof added

	if vc.Proof != nil {
		proofError := fmt.Errorf("vc with id %v already signed", vc.ID)
		err := vc.Verify(vcTypes.UseOldSignAlgorithm())
		if err != nil {
			return errors.Join(proofError, err)
		}
		return proofError
	}

	canonizeGo, err := vc.CanonizeGo()
	if err != nil {
		return err
	}

	jwsToken, hash, err := generateJWS(c.issuer.Alg, canonizeGo, c.issuer.Key)
	if err != nil {
		return err
	}

	proof := &vcTypes.Proof{
		Type:               "JsonWebSignature2020",
		Created:            time.Now().UTC().Format(time.RFC3339),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: c.issuer.VerificationMethod,
		JWS:                string(jwsToken),
	}

	publicKey, err := c.issuer.Key.PublicKey()
	if err != nil {
		return err
	}

	a, err := jws.Verify(jwsToken, jws.WithDetachedPayload([]byte(hash)), jws.WithKey(c.issuer.Alg, publicKey))
	if err != nil {
		return err
	}

	if string(a) != hash {
		return errors.New("internal error: hashes don't match")
	}

	vc.Proof = &vcTypes.Proofs{Proofs: []*vcTypes.Proof{proof}, WasSlice: false}

	return nil
}

func (c *TagusCompliance) SelfSignPresentation(_ *vcTypes.VerifiablePresentation, _ time.Duration) error {
	return errors.New("not supported by tagus")
}

func (c *TagusCompliance) ReSelfSign(credential *vcTypes.VerifiableCredential) error {
	credential.Proof = nil
	_, err := c.SelfSignVC(credential)
	return err
}

func (c *TagusCompliance) SelfSignVC(vc *vcTypes.VerifiableCredential) (*vcTypes.VerifiableCredential, error) {
	if vc == nil {
		return nil, errors.New("vc can not be nil")
	}
	if vc.Proof != nil {
		proofError := fmt.Errorf("vc with id %v already signed", vc.ID)
		err := vc.Verify(vcTypes.UseOldSignAlgorithm())
		if err != nil {
			return nil, errors.Join(proofError, err)
		}
		return nil, proofError
	}
	vc.Issuer = c.issuer.Issuer
	vc.IssuanceDate = time.Now().UTC().Format(time.RFC3339)

	n, err := vc.CanonizeGo()
	if err != nil {
		return nil, err
	}

	log.Println(string(n))

	jwsToken, _, err := c.generateJWS(n)
	if err != nil {
		return nil, err
	}

	proof := &vcTypes.Proof{
		Type:               "JsonWebSignature2020",
		Created:            time.Now().UTC().Format(time.RFC3339),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: c.issuer.VerificationMethod,
		JWS:                string(jwsToken),
	}

	vc.Proof = &vcTypes.Proofs{Proofs: []*vcTypes.Proof{proof}, WasSlice: false}

	err = vc.Validate(c.validate)
	if err != nil {
		return nil, err
	}

	err = vc.Verify(vcTypes.UseOldSignAlgorithm())
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (c *TagusCompliance) SelfVerify(vc *vcTypes.VerifiableCredential) error {

	proof := vc.Proof
	vc.Proof = nil

	canonizeGo, err := vc.CanonizeGo()
	if err != nil {
		return err
	}

	vc.Proof = proof

	hash := vcTypes.GenerateHash(canonizeGo)

	h := vcTypes.EncodeToString(hash)

	publicKey, err := c.issuer.Key.PublicKey()
	if err != nil {
		return err
	}

	a, err := jws.Verify([]byte(vc.Proof.Proofs[0].JWS), jws.WithDetachedPayload([]byte(h)), jws.WithKey(c.issuer.Alg, publicKey))
	if err != nil {
		return err
	}
	if string(a) != h {
		return errors.New("hashes do not match")
	}
	return nil
}

func (c *TagusCompliance) SignLegalRegistrationNumber(options LegalRegistrationNumberOptions) (*vcTypes.VerifiableCredential, error) {
	err := c.validate.Struct(options)
	if err != nil {
		return nil, err
	}

	rn := gxTypes.RegistrationNumber2210Struct{
		Context: vcTypes.Context{Context: []vcTypes.Namespace{participantNamespace}},
		Type:    "gx:legalRegistrationNumber",
		ID:      options.Id,
	}

	switch options.Type {
	case VatID:
		rn.GxVatID = options.RegistrationNumber
	case LeiCode:
		rn.GxLeiCode = options.RegistrationNumber
	case EORI:
		rn.GXEORI = options.RegistrationNumber
	case EUID:
		rn.GXEUID = options.RegistrationNumber
	case TaxID:
		rn.GXTaxID = options.RegistrationNumber
	default:
		return nil, errors.New("not implemented")
	}

	rnj, err := json.MarshalIndent(rn, "", "    ")
	if err != nil {
		return nil, errors.New("internal")
	}

	escapedId := url.QueryEscape(options.Id)

	req, err := http.NewRequest("POST", c.notaryURL.RegistrationNumberURL()+"?vcid="+escapedId, bytes.NewBuffer(rnj))
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
	log.Println(string(credential))
	cred := &vcTypes.VerifiableCredential{}
	err = json.Unmarshal(credential, cred)
	if err != nil {
		return nil, err
	}

	return cred, nil
}

func (c *TagusCompliance) SignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error) {
	tc := &gxTypes.TermsAndConditions2210Struct{
		Context:              vcTypes.Context{Context: []vcTypes.Namespace{trustFrameworkNamespace}},
		Type:                 "gx:GaiaXTermsAndConditions",
		GxTermsAndConditions: "The PARTICIPANT signing the Self-Description agrees as follows:\n- to update its descriptions about any changes, be it technical, organizational, or legal - especially but not limited to contractual in regards to the indicated attributes present in the descriptions.\n\nThe keypair used to sign Verifiable Credentials will be revoked where Gaia-X Association becomes aware of any inaccurate statements in regards to the claims which result in a non-compliance with the Trust Framework and policy rules defined in the Policy Rules and Labelling Document (PRLD).",
		ID:                   id,
	}

	tcMAP := map[string]interface{}{}

	tcJ, err := json.Marshal(tc)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(tcJ, &tcMAP)
	if err != nil {
		return nil, err
	}

	vc := &vcTypes.VerifiableCredential{
		Context: vcTypes.Context{Context: []vcTypes.Namespace{
			vcTypes.W3Credentials,
			vcTypes.SecuritySuitesJWS2020,
			trustFrameworkNamespace,
		}},
		Type:              vcTypes.VCType{Types: []string{"VerifiableCredential"}},
		IssuanceDate:      time.Now().UTC().Format(time.RFC3339),
		Issuer:            c.issuer.Issuer,
		ID:                id,
		CredentialSubject: vcTypes.CredentialSubject{CredentialSubject: []map[string]interface{}{tcMAP}},
	}

	signedVC, err := c.SelfSignVC(vc)
	if err != nil {
		return nil, err
	}

	vp := vcTypes.NewEmptyVerifiablePresentation()

	vp.VerifiableCredential = append(vp.VerifiableCredential, signedVC)

	vpJ, err := json.MarshalIndent(vp, "", "	")
	if err != nil {
		return nil, err
	}

	escapedId := url.QueryEscape(id)

	req, err := http.NewRequest("POST", c.signUrl.String()+"?vcid="+escapedId, bytes.NewBuffer(vpJ))
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
	if resp.StatusCode != 201 {
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

	cred := &vcTypes.VerifiableCredential{}
	err = json.Unmarshal(credential, cred)
	if err != nil {
		return nil, err
	}

	return cred, nil
}

func (c *TagusCompliance) SelfSignCredentialSubject(id string, credentialSubject []map[string]interface{}) (*vcTypes.VerifiableCredential, error) {
	vc := &vcTypes.VerifiableCredential{
		Context: vcTypes.Context{Context: []vcTypes.Namespace{
			vcTypes.W3Credentials,
			vcTypes.SecuritySuitesJWS2020,
			trustFrameworkNamespace,
		}},
		Type:              vcTypes.VCType{Types: []string{"VerifiableCredential"}},
		IssuanceDate:      time.Now().UTC().Format(time.RFC3339),
		Issuer:            c.issuer.Issuer,
		ID:                id,
		CredentialSubject: vcTypes.CredentialSubject{CredentialSubject: credentialSubject},
	}

	signedVC, err := c.SelfSignVC(vc)
	if err != nil {
		return nil, err
	}
	return signedVC, nil
}

func (c *TagusCompliance) GaiaXSignParticipant(options ParticipantComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error) {
	err := c.validate.Struct(options)
	if err != nil {
		return nil, nil, err
	}

	vp := vcTypes.NewEmptyVerifiablePresentation()

	err = options.BuildParticipantVC()
	if err != nil {
		return nil, nil, err
	}

	options.participantVC.CredentialsStatus = map[string]interface{}{
		"id":                   "https://example.com/credentials/status/3#94567",
		"type":                 "BitstringStatusListEntry",
		"statusPurpose":        "revocation",
		"statusListIndex":      "94567",
		"statusListCredential": "https://example.com/credentials/status/3",
	}

	options.participantVC.Context.Context = append(options.participantVC.Context.Context, vcTypes.Namespace{URL: "https://www.w3.org/ns/credentials/status/v1"})
	//options.participantVC.Context.Context = append(options.participantVC.Context.Context, vcTypes.Namespace{URL: "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry"})

	options.participantVC, err = c.SelfSignVC(options.participantVC)
	if err != nil {
		return nil, nil, err
	}

	err = c.SelfVerify(options.participantVC)
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}

	vp.VerifiableCredential = append(vp.VerifiableCredential, options.participantVC, options.LegalRegistrationNumberVC, options.TermAndConditionsVC)

	vpJ, err := json.MarshalIndent(vp, "", "	")
	if err != nil {
		return nil, nil, err
	}

	//log.Println(string(vpJ))

	req, err := http.NewRequest("POST", c.signUrl.String(), bytes.NewBuffer(vpJ))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode != 201 {
		errBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, err
		}
		return nil, vp, fmt.Errorf("signing was not successful: %v", string(errBody))
	}

	credential, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	cred := &vcTypes.VerifiableCredential{}
	err = json.Unmarshal(credential, cred)
	if err != nil {
		return nil, nil, err
	}

	return cred, vp, nil

}

func (c *TagusCompliance) SelfSignSignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error) {
	tc := &gxTypes.TermsAndConditions2210Struct{
		Context:              vcTypes.Context{Context: []vcTypes.Namespace{trustFrameworkNamespace}},
		Type:                 "gx:GaiaXTermsAndConditions",
		GxTermsAndConditions: "The PARTICIPANT signing the Self-Description agrees as follows:\n- to update its descriptions about any changes, be it technical, organizational, or legal - especially but not limited to contractual in regards to the indicated attributes present in the descriptions.\n\nThe keypair used to sign Verifiable Credentials will be revoked where Gaia-X Association becomes aware of any inaccurate statements in regards to the claims which result in a non-compliance with the Trust Framework and policy rules defined in the Policy Rules and Labelling Document (PRLD).",
		ID:                   id,
	}

	tcMAP := map[string]interface{}{}

	tcJ, err := json.Marshal(tc)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(tcJ, &tcMAP)
	if err != nil {
		return nil, err
	}

	vc := &vcTypes.VerifiableCredential{
		Context: vcTypes.Context{Context: []vcTypes.Namespace{
			vcTypes.W3Credentials,
			vcTypes.SecuritySuitesJWS2020,
			trustFrameworkNamespace,
		}},
		Type:              vcTypes.VCType{Types: []string{"VerifiableCredential"}},
		IssuanceDate:      time.Now().UTC().Format(time.RFC3339),
		Issuer:            c.issuer.Issuer,
		ID:                id,
		CredentialSubject: vcTypes.CredentialSubject{CredentialSubject: []map[string]interface{}{tcMAP}},
	}

	signedVC, err := c.SelfSignVC(vc)
	if err != nil {
		return nil, err
	}

	return signedVC, nil
}

func (c *TagusCompliance) SignServiceOffering(options ServiceOfferingComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	return c.SignServiceOfferingWithContext(ctx, options)
}

func (c *TagusCompliance) SignServiceOfferingWithContext(ctx context.Context, options ServiceOfferingComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error) {
	err := c.validate.Struct(options)
	if err != nil {
		return nil, nil, err
	}

	err = options.BuildVC()
	if err != nil {
		return nil, nil, err
	}

	options.ParticipantComplianceOptions.participantVC, err = c.SelfSignVC(options.ParticipantComplianceOptions.participantVC)
	if err != nil {
		return nil, nil, err
	}

	options.serviceOfferingVC, err = c.SelfSignVC(options.serviceOfferingVC)
	if err != nil {
		return nil, nil, err
	}

	registrationNumber := options.ParticipantComplianceOptions.LegalRegistrationNumberVC
	termsAndConditions := options.ParticipantComplianceOptions.TermAndConditionsVC

	vp := vcTypes.NewEmptyVerifiablePresentation()

	vp.VerifiableCredential = append(vp.VerifiableCredential, registrationNumber, termsAndConditions, options.ParticipantComplianceOptions.participantVC, options.serviceOfferingVC)

	vpJ, err := json.MarshalIndent(vp, "", "	")
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.signUrl.String(), bytes.NewBuffer(vpJ))
	if err != nil {
		return nil, nil, err
	}

	log.Println(string(vpJ))

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode != 201 {
		errBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, err
		}
		return nil, vp, fmt.Errorf("signing was not successful: %v", string(errBody))
	}

	credential, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	cred := &vcTypes.VerifiableCredential{}
	err = json.Unmarshal(credential, cred)
	if err != nil {
		return nil, nil, err
	}

	return cred, vp, nil
}

func (c *TagusCompliance) GetTermsAndConditions(url RegistryUrl) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url.String()+"api/termsAndConditions", http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode != 200 {
		errBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("could not get terms and conditions: %v", string(errBody))
	}

	tc, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(tc), nil
}

// generateJWS sd has to be the normalized sd
func (c *TagusCompliance) generateJWS(sd []byte) ([]byte, string, error) {
	hash := hash256(sd)

	header := jws.NewHeaders()
	err := header.Set("b64", false)
	if err != nil {
		return nil, "", err
	}
	err = header.Set("crit", []string{"b64"})
	if err != nil {
		return nil, "", err
	}

	buf, err := jws.Sign(nil, jws.WithKey(c.issuer.Alg, c.issuer.Key, jws.WithProtectedHeaders(header)), jws.WithDetachedPayload([]byte(hash)))
	if err != nil {
		return nil, "", err
	}

	return buf, hash, nil
}

// deprecated
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

type ParticipantV1OptionsAsMap struct {
	ParticipantCredentialSubject []map[string]interface{}
}

func (pm ParticipantV1OptionsAsMap) BuildParticipantVC(id string) (*vcTypes.VerifiableCredential, error) {
	vc := vcTypes.NewEmptyVerifiableCredential()
	vc.Context.Context = append(vc.Context.Context, vcTypes.SecuritySuitesJWS2020, trustFrameworkNamespace)
	vc.ID = id
	vc.CredentialSubject.CredentialSubject = pm.ParticipantCredentialSubject
	return vc, nil
}

// generateJWS sd has to be the normalized sd
func generateJWS(alg jwa.SignatureAlgorithm, sd []byte, privateKey jwk.Key) ([]byte, string, error) {
	hash := hash256(sd)

	header := jws.NewHeaders()
	err := header.Set("b64", false)
	if err != nil {
		return nil, "", err
	}
	err = header.Set("crit", []string{"b64"})
	if err != nil {
		return nil, "", err
	}

	buf, err := jws.Sign(nil, jws.WithKey(alg, privateKey, jws.WithProtectedHeaders(header)), jws.WithDetachedPayload([]byte(hash)))
	if err != nil {
		return nil, "", err
	}

	return buf, hash, nil
}
