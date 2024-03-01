/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package compliance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	if vc.Proof != nil {
		proofError := fmt.Errorf("vc with id %v already signed", vc.ID)
		err := vc.Verify()
		if err != nil {
			return nil, errors.Join(proofError, err)
		}
		return nil, proofError
	}
	vc.Issuer = c.issuer
	vc.IssuanceDate = time.Now().UTC().Format(time.RFC3339)

	n, err := vc.CanonizeGo()
	if err != nil {
		return nil, err
	}

	proof := &vcTypes.Proof{
		Type:               "JsonWebSignature2020",
		Created:            time.Now().UTC().Format(time.RFC3339),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: c.verificationMethod,
		JWS:                "",
	}

	normalize, err := proof.Normalize(vc)
	if err != nil {
		return nil, err
	}

	jwsToken, _, err := c.generateJWS(n, normalize)
	if err != nil {
		return nil, err
	}

	proof.JWS = string(jwsToken)

	vc.Proof = &vcTypes.Proofs{Proofs: []*vcTypes.Proof{proof}, WasSlice: false}

	err = vc.Validate(c.validate)
	if err != nil {
		return nil, err
	}

	err = vc.Verify()
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (c *LoireCompliance) SelfVerify(vc *vcTypes.VerifiableCredential) error {

	proof := vc.Proof
	vc.Proof = nil

	canonizeGo, err := vc.CanonizeGo()
	if err != nil {
		return err
	}

	normalizeProof, err := proof.Proofs[0].Normalize(vc)
	if err != nil {
		return err
	}

	vc.Proof = proof

	sdHash := vcTypes.GenerateHash(canonizeGo)
	proofHash := vcTypes.GenerateHash(normalizeProof)

	h := bytes.Join([][]byte{proofHash, sdHash}, []byte{})

	publicKey, err := c.key.PublicKey()
	if err != nil {
		return err
	}

	a, err := jws.Verify([]byte(vc.Proof.Proofs[0].JWS), jws.WithDetachedPayload(h), jws.WithKey(jwa.PS256, publicKey))
	if err != nil {
		return err
	}
	if vcTypes.EncodeToString(a) != vcTypes.EncodeToString(h) {
		return errors.New("hashes do not match")
	}
	return nil
}

func (c *LoireCompliance) SignLegalRegistrationNumber(options LegalRegistrationNumberOptions) (*vcTypes.VerifiableCredential, error) {
	err := c.validate.Struct(options)
	if err != nil {
		return nil, err
	}

	rn := vcTypes.RegistrationNumber2210Struct{
		Context: vcTypes.Context{Context: []string{participantURL}},
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

	req, err := http.NewRequest("POST", string(c.registrationNumberUrl)+"?vcid="+escapedId, bytes.NewBuffer(rnj))
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
	cred := &vcTypes.VerifiableCredential{}
	err = json.Unmarshal(credential, cred)
	if err != nil {
		return nil, err
	}

	return cred, nil
}

func (c *LoireCompliance) SignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error) {
	tc := &vcTypes.TermsAndConditions2210Struct{
		Context:              vcTypes.Context{Context: []string{trustFrameWorkURL}},
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
		Context: vcTypes.Context{Context: []string{
			vcTypes.W3Credentials,
			"https://w3id.org/security/suites/jws-2020/v1",
			trustFrameWorkURL,
		}},
		Type:              vcTypes.VCType{Types: []string{"VerifiableCredential"}},
		IssuanceDate:      time.Now().UTC().Format(time.RFC3339),
		Issuer:            c.issuer,
		ID:                id,
		CredentialSubject: vcTypes.CredentialSubject{CredentialSubject: []map[string]interface{}{tcMAP}},
	}

	signedVC, err := c.SelfSignVC(vc)
	if err != nil {
		return nil, errors.Join(errors.New("error on self sign vc"), err)
	}

	vp := vcTypes.NewEmptyVerifiablePresentation()

	vp.VerifiableCredential = append(vp.VerifiableCredential, signedVC)

	vpJ, err := json.MarshalIndent(vp, "", "	")
	if err != nil {
		return nil, err
	}

	log.Println(string(vpJ))

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

func (c *LoireCompliance) SelfSignCredentialSubject(id string, credentialSubject []map[string]interface{}) (*vcTypes.VerifiableCredential, error) {
	vc := &vcTypes.VerifiableCredential{
		Context: vcTypes.Context{Context: []string{
			vcTypes.W3Credentials,
			"https://w3id.org/security/suites/jws-2020/v1",
			trustFrameWorkURL,
		}},
		Type:              vcTypes.VCType{Types: []string{"VerifiableCredential"}},
		IssuanceDate:      time.Now().UTC().Format(time.RFC3339),
		Issuer:            c.issuer,
		ID:                id,
		CredentialSubject: vcTypes.CredentialSubject{CredentialSubject: credentialSubject},
	}

	signedVC, err := c.SelfSignVC(vc)
	if err != nil {
		return nil, err
	}
	return signedVC, nil
}

func (c *LoireCompliance) GaiaXSignParticipant(options ParticipantComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error) {
	err := c.validate.Struct(options)
	if err != nil {
		return nil, nil, err
	}

	vp := vcTypes.NewEmptyVerifiablePresentation()

	err = options.BuildParticipantVC()
	if err != nil {
		return nil, nil, err
	}

	options.participantVC, err = c.SelfSignVC(options.participantVC)
	if err != nil {
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

func (c *LoireCompliance) SelfSignSignTermsAndConditions(id string) (*vcTypes.VerifiableCredential, error) {
	tc := &vcTypes.TermsAndConditions2210Struct{
		Context:              vcTypes.Context{Context: []string{trustFrameWorkURL}},
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
		Context: vcTypes.Context{Context: []string{
			vcTypes.W3Credentials,
			"https://w3id.org/security/suites/jws-2020/v1",
			trustFrameWorkURL,
		}},
		Type:              vcTypes.VCType{Types: []string{"VerifiableCredential"}},
		IssuanceDate:      time.Now().UTC().Format(time.RFC3339),
		Issuer:            c.issuer,
		ID:                id,
		CredentialSubject: vcTypes.CredentialSubject{CredentialSubject: []map[string]interface{}{tcMAP}},
	}

	signedVC, err := c.SelfSignVC(vc)
	if err != nil {
		return nil, err
	}

	return signedVC, nil
}

func (c *LoireCompliance) SignServiceOffering(options ServiceOfferingComplianceOptions) (*vcTypes.VerifiableCredential, *vcTypes.VerifiablePresentation, error) {
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

func (c *LoireCompliance) GetTermsAndConditions(url RegistryUrl) (string, error) {
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
func (c *LoireCompliance) generateJWS(sd []byte, proof []byte) ([]byte, string, error) {
	sdHash := vcTypes.GenerateHash(sd)
	hash := sdHash
	var proofHash []byte
	if len(proof) > 0 {
		//log.Printf("before hash %v", proof)
		proofHash = vcTypes.GenerateHash(proof)
		hash = bytes.Join([][]byte{proofHash, sdHash}, []byte{})
		//log.Printf("hash: %v len: %v", proofHash, len(hash))
	}

	header := jws.NewHeaders()
	err := header.Set("b64", false)
	if err != nil {
		return nil, "", err
	}
	err = header.Set("crit", []string{"b64"})
	if err != nil {
		return nil, "", err
	}

	buf, err := jws.Sign(nil, jws.WithKey(jwa.PS256, c.key, jws.WithProtectedHeaders(header)), jws.WithDetachedPayload(hash))
	if err != nil {
		return nil, "", err
	}
	h := vcTypes.EncodeToString(hash)

	return buf, h, nil
}
