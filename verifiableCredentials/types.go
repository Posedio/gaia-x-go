/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package verifiableCredentials

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gowebpki/jcs"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/piprate/json-gold/ld"
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/did"
)

const W3Credentials = "https://www.w3.org/2018/credentials/v1"
const SecuritySuitesJWS2020 = "https://w3id.org/security/suites/jws-2020/v1"

// VerifiablePresentation implements the shape of a verifiable presentation as defined in: https://www.w3.org/TR/vc-data-model/#presentations
// since Gaia-X has not defined a proof method yet, this is still open
type VerifiablePresentation struct {
	Context              string                  `json:"@context" validate:"required"`
	Type                 string                  `json:"type" validate:"required"`
	VerifiableCredential []*VerifiableCredential `json:"verifiableCredential" validate:"required"`
	Proof                *Proofs                 `json:"proof,omitempty"`
}

func NewEmptyVerifiablePresentation() *VerifiablePresentation {
	return &VerifiablePresentation{
		Context:              W3Credentials,
		Type:                 "VerifiablePresentation",
		VerifiableCredential: make([]*VerifiableCredential, 0),
		Proof:                nil,
	}
}

// ToMap returns the map[string]interface{} representation of the VP, this a deep copy
func (vp *VerifiablePresentation) ToMap() (map[string]interface{}, error) {
	marshal, err := json.Marshal(vp)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}

	err = json.Unmarshal(marshal, &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (vp *VerifiablePresentation) String() string {
	marshal, err := json.MarshalIndent(vp, "", "  ")
	if err != nil {
		return ""
	}
	return string(marshal)
}

func (vp *VerifiablePresentation) ToJson() ([]byte, error) {
	marshal, err := json.Marshal(vp)
	if err != nil {
		return nil, err
	}
	return marshal, nil
}

func (vp *VerifiablePresentation) ToBase64() (string, error) {
	toJson, err := vp.ToJson()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(toJson), nil
}

func NewEmptyVerifiableCredential() *VerifiableCredential {
	vc := &VerifiableCredential{}

	// only a valid vc with the context
	vc.Context = Context{
		wasSlice: true,
		Context:  []string{W3Credentials},
	}

	// only a valid vc with type set
	vc.Type = VCType{
		wasSlice: true,
		Types:    []string{"VerifiableCredential"},
	}

	vc.CredentialSubject = CredentialSubject{
		CredentialSubject: make([]map[string]interface{}, 1),
	}
	vc.Proof = nil

	return vc
}

// VerifiableCredential implements the shape of a VC as defined in https://www.w3.org/TR/vc-data-model/#basic-concepts
type VerifiableCredential struct {
	Context           Context           `json:"@context" validate:"required"`
	Type              VCType            `json:"type" validate:"required"`
	IssuanceDate      string            `json:"issuanceDate" validate:"required"`
	ExpirationDate    string            `json:"expirationDate,omitempty"`
	CredentialSubject CredentialSubject `json:"credentialSubject,omitempty"`
	Issuer            string            `json:"issuer" validate:"required"`
	ID                string            `json:"id" validate:"required"`
	Proof             *Proofs           `json:"proof,omitempty"`
	Evidence          []struct {
		GxEvidenceURL   string `json:"gx:evidenceURL,omitempty"`
		GxExecutionDate string `json:"gx:executionDate,omitempty"`
		GxEvidenceOf    string `json:"gx:evidenceOf,omitempty"`
	} `json:"evidence,omitempty"`
	proc    *ld.JsonLdProcessor
	Options *ld.JsonLdOptions `json:"-"`
	mux     sync.Mutex
}

func (c *VerifiableCredential) ToMap() (map[string]interface{}, error) {
	marshal, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}

	err = json.Unmarshal(marshal, &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (c *VerifiableCredential) ToJson() ([]byte, error) {
	marshal, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return marshal, nil
}

func (c *VerifiableCredential) ToBase64() (string, error) {
	toJson, err := c.ToJson()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(toJson), nil
}

func (c *VerifiableCredential) Validate(validate *validator.Validate) error {
	return validate.Struct(c)
}

func (c *VerifiableCredential) Verify() error {
	for _, proof := range c.Proof.Proofs {
		d, err := did.ResolveDIDWeb(proof.VerificationMethod)
		if err != nil {
			//fallback to universal resolver
			d, err = did.UniResolverDID(proof.VerificationMethod)
			if err != nil {
				return err
			}

		}

		err = d.ResolveMethods()
		if err != nil {
			return err
		}

		c.mux.Lock()
		defer c.mux.Unlock()

		p := c.Proof
		c.Proof = nil

		n, err := c.CanonizeGo()
		if err != nil {
			c.Proof = p
			return err
		}
		c.Proof = p

		hash := GenerateHash(n)

		key, ok := d.Keys[proof.VerificationMethod]
		if !ok {
			return fmt.Errorf("verfication method not defined in DID")
		}
		if !slices.Contains(key.AllowedMethods, did.AssertionMethod) {
			return fmt.Errorf("verfication method %v not allowed as %v", proof.VerificationMethod, did.AssertionMethod)
		}

		k := key.JWK

		//log.Println(k.X509URL())

		_, err = VerifyCertChain(k.X509URL())
		if err != nil {
			log.Println(err)
		}

		_, err = jws.Verify([]byte(proof.JWS), jws.WithKey(k.Algorithm(), k), jws.WithDetachedPayload([]byte(hash)))
		if err != nil {
			return err
		}

		return nil
	}
	return errors.New("has no proof")
}

func VerifyCertChain(url string) (*x509.Certificate, error) {
	c := http.Client{Timeout: time.Second * 2}
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	do, err := c.Do(request)
	if err != nil {
		return nil, err
	}
	if do.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cert not loadable: %v", do.Status)
	}
	certBytes, err := io.ReadAll(do.Body)
	if err != nil {
		return nil, err
	}
	block, next := pem.Decode(certBytes)
	if block == nil {
		return nil, errors.New("empty certificate block or malformed certificate ")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	for {
		block, next = pem.Decode(next)
		if block == nil {
			break
		}

		inter, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		//todo check /v1/api/trustAnchor/chain/file

		roots.AddCert(inter)
		if len(next) == 0 {
			break
		}
	}

	log.Printf("the domains %v, are singed from %v and are valid till %v and owned by %v", cert.DNSNames, cert.Issuer, cert.NotAfter, cert.Subject.String())

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		log.Println("certificate does not allow digital signature")
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		_, err = cert.Verify(x509.VerifyOptions{})
		if err != nil {
			return nil, err
		}

	}

	return cert, nil
}

func GenerateHash(sd []byte) string {
	h := sha256.Sum256(sd)
	hash := hex.EncodeToString(h[:])
	return hash
}

func (c *VerifiableCredential) CanonizeGo() ([]byte, error) {
	m, err := c.ToMap()
	if err != nil {
		return nil, err
	}

	if c.proc == nil || c.Options == nil {

		c.proc = ld.NewJsonLdProcessor()

		c.Options = ld.NewJsonLdOptions("")
		c.Options.UseRdfType = true
		c.Options.Format = "application/n-quads"
		c.Options.Algorithm = ld.AlgorithmURDNA2015

		// since the w3c website is not perfectly available retry it 10 times,
		// alternatively the document loader could cache the result
		retryClient := retryablehttp.NewClient()
		retryClient.RetryMax = 10
		retryClient.RetryWaitMax = 4000 * time.Millisecond
		retryClient.HTTPClient.Timeout = 3500 * time.Millisecond
		retryClient.Logger = nil
		retryClient.CheckRetry = DefaultRetryPolicy

		client := retryClient.StandardClient()

		loader := NewDocumentLoader(client)

		c.Options.DocumentLoader = loader

	}

	n, err := c.proc.Normalize(m, c.Options)
	if err != nil {
		if strings.Contains(err.Error(), string(ld.LoadingRemoteContextFailed)) {
			log.Println(err.Error())
		}
		return nil, fmt.Errorf("jsongold error: %v", err)
	}
	if re, k := n.(string); k {
		return []byte(re), nil
	}
	return nil, errors.New("could not convert to byte slice")
}

func (c *VerifiableCredential) JSC() ([]byte, error) {
	j, err := c.ToJson()
	if err != nil {
		return nil, err
	}

	trans, err := jcs.Transform(j)
	if err != nil {
		return nil, err
	}
	return trans, nil
}

func (c *VerifiableCredential) Hash() (string, error) {
	jsc, err := c.JSC()
	if err != nil {
		return "", err
	}
	hash := GenerateHash(jsc)
	return hash, nil
}

func (c *VerifiableCredential) String() string {
	marshal, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return ""
	}
	return string(marshal)
}

type Context struct {
	Context  []string
	wasSlice bool
}

func (c *Context) MarshalJSON() ([]byte, error) {
	if len(c.Context) == 1 && !c.wasSlice {
		credential, err := json.Marshal(c.Context[0])
		if err != nil {
			return nil, err
		}
		return credential, nil
	}
	var x []string
	x = c.Context
	credentials, err := json.Marshal(x)
	if err != nil {
		return nil, err
	}
	return credentials, nil
}

func (c *Context) UnmarshalJSON(dat []byte) error {
	var css []string
	err := json.Unmarshal(dat, &css)
	if err != nil {
		var co string
		err = json.Unmarshal(dat, &co)
		if err != nil {
			return err
		}
		css = append(css, co)
		c.Context = css
		c.wasSlice = false
	} else {
		c.Context = css
		c.wasSlice = true
	}
	return nil
}

type VCType struct {
	Types    []string
	wasSlice bool
}

func (t *VCType) MarshalJSON() ([]byte, error) {
	if len(t.Types) == 1 && !t.wasSlice {
		credential, err := json.Marshal(t.Types[0])
		if err != nil {
			return nil, err
		}
		return credential, nil
	}
	var x []string
	x = t.Types
	credentials, err := json.Marshal(x)
	if err != nil {
		return nil, err
	}
	return credentials, nil
}

func (t *VCType) UnmarshalJSON(dat []byte) error {
	var css []string
	err := json.Unmarshal(dat, &css)
	if err != nil {
		var co string
		err = json.Unmarshal(dat, &co)
		if err != nil {
			return err
		}
		css = append(css, co)
		t.Types = css
		t.wasSlice = false
	} else {
		t.Types = css
		t.wasSlice = true
	}
	return nil
}

type CredentialSubject struct {
	CredentialSubject []map[string]interface{}
	wasSlice          bool
}

func (cs *CredentialSubject) MarshalJSON() ([]byte, error) {
	if len(cs.CredentialSubject) == 1 && !cs.wasSlice {
		credential, err := json.Marshal(cs.CredentialSubject[0])
		if err != nil {
			return nil, err
		}
		return credential, nil
	}
	var x []map[string]interface{}
	x = cs.CredentialSubject

	credentials, err := json.Marshal(x)
	if err != nil {
		return nil, err
	}
	return credentials, nil
}

func (cs *CredentialSubject) UnmarshalJSON(dat []byte) error {
	var css []map[string]interface{}
	err := json.Unmarshal(dat, &css)
	if err != nil {
		var co map[string]interface{}
		err = json.Unmarshal(dat, &co)
		if err != nil {
			return err
		}
		css = append(css, co)
		cs.CredentialSubject = css
		cs.wasSlice = false
	} else {
		cs.CredentialSubject = css
		cs.wasSlice = true
	}
	return nil
}

type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	ProofPurpose       string `json:"proofPurpose"`
	VerificationMethod string `json:"verificationMethod"`
	JWS                string `json:"jws"`
}

type Proofs struct {
	Proofs   []*Proof
	WasSlice bool
}

func (cs *Proofs) MarshalJSON() ([]byte, error) {
	if len(cs.Proofs) == 1 && !cs.WasSlice {
		credential, err := json.Marshal(cs.Proofs[0])
		if err != nil {
			return nil, err
		}
		return credential, nil
	}
	var x []*Proof
	x = cs.Proofs

	credentials, err := json.Marshal(x)
	if err != nil {
		return nil, err
	}
	return credentials, nil
}

func (cs *Proofs) UnmarshalJSON(dat []byte) error {
	var css []*Proof
	err := json.Unmarshal(dat, &css)
	if err != nil {
		co := &Proof{}
		err = json.Unmarshal(dat, co)
		if err != nil {
			return err
		}
		css = append(css, co)
		cs.Proofs = css
		cs.WasSlice = false
	} else {
		cs.Proofs = css
		cs.WasSlice = true
	}
	return nil
}
