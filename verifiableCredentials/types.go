/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package verifiableCredentials

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Posedio/gaia-x-go/did"
	"github.com/go-playground/validator/v10"
	"github.com/gowebpki/jcs"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/piprate/json-gold/ld"
)

const W3CredentialsUrl = "https://www.w3.org/2018/credentials/v1"  // #nosec
const W3CCredentialsUrlV2 = "https://www.w3.org/ns/credentials/v2" // #nosec

const W3CEnvelopedVerifiableCredential = "EnvelopedVerifiableCredential"

var W3Credentials = Namespace{
	Namespace: "",
	URL:       W3CredentialsUrl,
}

var W3CredentialsV2 = Namespace{
	Namespace: "",
	URL:       W3CCredentialsUrlV2,
}

const SecuritySuitesJWS2020Url = "https://w3id.org/security/suites/jws-2020/v1"

var SecuritySuitesJWS2020 = Namespace{
	Namespace: "",
	URL:       SecuritySuitesJWS2020Url,
}

// VerifiablePresentation implements the shape of a verifiable presentation as defined in: https://www.w3.org/TR/vc-data-model/#presentations
// since Gaia-X has not defined a proof method yet, this is still open
type VerifiablePresentation struct {
	Context              string                  `json:"@context" validate:"required"`
	Type                 string                  `json:"type" validate:"required"`
	VerifiableCredential []*VerifiableCredential `json:"verifiableCredential" validate:"required"`
	Proof                *Proofs                 `json:"proof,omitempty"`
	Issuer               string                  `json:"issuer,omitempty,omitzero" validate:"omitempty"`
	ValidFrom            time.Time               `json:"validFrom,omitzero" validate:"omitempty"`
	ValidUntil           time.Time               `json:"validUntil,omitzero" validate:"omitempty"`
	signature            *JWSSignature
	decodedCredentials   []*VerifiableCredential
	proc                 *ld.JsonLdProcessor
	Options              *ld.JsonLdOptions `json:"-"`
	mux                  sync.Mutex
	once                 sync.Once
}

func NewEmptyVerifiablePresentation() *VerifiablePresentation {
	return &VerifiablePresentation{
		Context:              W3CredentialsUrl,
		Type:                 "VerifiablePresentation",
		VerifiableCredential: make([]*VerifiableCredential, 0),
		Proof:                nil,
	}
}

func NewEmptyVerifiablePresentationV2() *VerifiablePresentation {
	return &VerifiablePresentation{
		Context:              W3CCredentialsUrlV2,
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

func (vp *VerifiablePresentation) AddEnvelopedVC(jws []byte) {
	vp.VerifiableCredential = append(vp.VerifiableCredential, &VerifiableCredential{
		Context: Context{
			wasSlice: false,
			Context: []Namespace{{
				Namespace: "",
				URL:       "https://www.w3.org/ns/credentials/v2",
			}},
		},
		Type: VCType{
			wasSlice: false,
			Types:    []string{W3CEnvelopedVerifiableCredential},
		},
		ID: "data:application/vc+jwt," + string(jws),
	})
}

func (vp *VerifiablePresentation) DecodeEnvelopedCredentials() ([]*VerifiableCredential, error) {
	if vp.decodedCredentials == nil {
		vp.decodedCredentials = make([]*VerifiableCredential, len(vp.VerifiableCredential))
	}
	for i, vc := range vp.VerifiableCredential {
		v := new(VerifiableCredential)
		var err error
		if vc.GetOriginalJWS() != nil {
			v, err = VCFromJWT(vc.GetOriginalJWS())
		} else if slices.Contains(vc.Type.Types, W3CEnvelopedVerifiableCredential) {
			jwt, err := JWTFromID(vc.ID)
			if err != nil {
				return nil, err
			}
			v, err = VCFromJWT(jwt)
		} else if slices.Contains(vc.Type.Types, "VerifiableCredential") { //todo untested
			v = vc
		} else {
			return nil, fmt.Errorf("invalid VC at index: %v", i)
		}
		if err != nil {
			return nil, err
		}
		vp.decodedCredentials[i] = v
	}
	return vp.decodedCredentials, nil
}

func (vp *VerifiablePresentation) setupJsonLdProcessor() {
	vp.proc = ld.NewJsonLdProcessor()

	vp.Options = ld.NewJsonLdOptions("")
	vp.Options.UseRdfType = true
	vp.Options.Format = "application/n-quads"
	vp.Options.Algorithm = ld.AlgorithmURDNA2015

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

	vp.Options.DocumentLoader = loader
}

func (vp *VerifiablePresentation) Expand() ([][]byte, error) {
	m, err := vp.ToMap()
	if err != nil {
		return nil, err
	}

	vp.once.Do(vp.setupJsonLdProcessor)

	options := ld.NewJsonLdOptions("")

	options.Explicit = true

	n, err := vp.proc.Expand(m, options)
	if err != nil {
		if strings.Contains(err.Error(), string(ld.LoadingRemoteContextFailed)) {
			log.Println(err.Error())
		}
		return nil, fmt.Errorf("jsongold error: %v", err)
	}

	l := make([][]byte, len(n))

	for i, ele := range n {
		marshal, err := json.Marshal(ele)
		if err != nil {
			return nil, err
		}
		l[i] = marshal
	}
	return l, nil
}

func NewEmptyVerifiableCredential() *VerifiableCredential {
	vc := &VerifiableCredential{}

	// only a valid vc with the context
	vc.Context = Context{
		wasSlice: true,
		Context:  []Namespace{W3Credentials},
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

func NewEmptyVerifiableCredentialV2(options ...VerifiableCredentialOption) (*VerifiableCredential, error) {
	vc := &VerifiableCredential{}

	// only a valid vc with the context
	vc.Context = Context{
		wasSlice: true,
		Context:  []Namespace{W3CredentialsV2},
	}

	// only a valid vc with type set
	vc.Type = VCType{
		wasSlice: true,
		Types:    []string{"VerifiableCredential"},
	}

	vc.CredentialSubject = CredentialSubject{
		CredentialSubject: make([]map[string]interface{}, 0),
	}
	vc.Proof = nil

	for _, option := range options {
		err := option.apply(vc)
		if err != nil {
			return nil, err
		}
	}

	return vc, nil
}

type VerifiableCredentialOption interface {
	apply(option *VerifiableCredential) error
}

type baseVCOption struct {
	f func(vc *VerifiableCredential) error
}

func (vco *baseVCOption) apply(option *VerifiableCredential) error {
	return vco.f(option)
}

func WithVCID(id string) VerifiableCredentialOption {
	return &baseVCOption{
		f: func(vc *VerifiableCredential) error {
			vc.ID = id
			return nil
		},
	}
}

func WithValidFromNow() VerifiableCredentialOption {
	return &baseVCOption{
		f: func(vc *VerifiableCredential) error {
			vc.ValidFrom = time.Now()
			return nil
		},
	}
}

func WithAdditionalTypes(types ...string) VerifiableCredentialOption {
	return &baseVCOption{
		f: func(vc *VerifiableCredential) error {
			for _, t := range types {
				vc.Type.Types = append(vc.Type.Types, t)
			}
			return nil
		},
	}
}

func WithIssuer(issuer string) VerifiableCredentialOption {
	return &baseVCOption{
		f: func(vc *VerifiableCredential) error {
			vc.Issuer = issuer
			return nil
		},
	}
}

func WithGaiaXContext() VerifiableCredentialOption {
	return &baseVCOption{
		f: func(vc *VerifiableCredential) error {
			vc.Context.Context = append(vc.Context.Context, Namespace{
				Namespace: "",
				URL:       "https://w3id.org/gaia-x/development#",
			})
			return nil
		},
	}
}

const JWTType = "vc+ld+jwt"
const JWTCTY = "vc+ld"

type JWSSignature struct {
	OriginalJWT []byte
	DID         *did.DID
	JWTHeader   *JWTHeader
}

// VerifiableCredential implements the shape of a VC as defined in https://www.w3.org/TR/vc-data-model/#basic-concepts
type VerifiableCredential struct {
	Context           Context           `json:"@context" validate:"required"`
	Type              VCType            `json:"type" validate:"required"`
	IssuanceDate      string            `json:"issuanceDate,omitempty,omitzero" validate:"omitempty"`
	ExpirationDate    string            `json:"expirationDate,omitempty,omitzero"`
	CredentialSubject CredentialSubject `json:"credentialSubject,omitempty,omitzero" validate:"omitempty"`
	Issuer            string            `json:"issuer,omitzero" validate:"omitempty"`
	ID                string            `json:"id" validate:"required"`
	ValidFrom         time.Time         `json:"validFrom,omitzero" validate:"omitempty"`
	ValidUntil        time.Time         `json:"validUntil,omitzero" validate:"omitempty"`
	Name              string            `json:"name,omitempty" validate:"omitempty"`
	Proof             *Proofs           `json:"proof,omitempty"`
	Evidence          any               `json:"evidence,omitempty"`
	proc              *ld.JsonLdProcessor
	Options           *ld.JsonLdOptions `json:"-"`
	mux               sync.Mutex
	once              sync.Once
	signature         *JWSSignature
	//verifyOptions     verifyOptions
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

func (c *VerifiableCredential) GetOriginalJWS() []byte {
	if c.signature != nil {
		return c.signature.OriginalJWT
	}
	return nil
}

func (c *VerifiableCredential) AddSignature(originalJWS []byte) error {
	dids, err := VerifyJWS(originalJWS)
	if err != nil {
		return err
	}
	var signaturesErr error

	for didweb, header := range dids {
		key, k := didweb.Keys[header.KID]
		if !k {
			signaturesErr = errors.Join(signaturesErr, fmt.Errorf("key %v not in did web %v", header.KID, header.Issuer))
			continue
		}

		payload, err := jws.Verify(originalJWS, jws.WithKey(header.Algorithm, key.JWK))
		if err != nil {
			signaturesErr = errors.Join(signaturesErr, err)
			continue
		}

		vc := &VerifiableCredential{}

		err = json.Unmarshal(payload, vc)
		if err != nil {
			signaturesErr = errors.Join(signaturesErr, err)
			continue
		}
		c.signature = &JWSSignature{
			OriginalJWT: originalJWS,
			DID:         didweb,
			JWTHeader:   header,
		}

		return nil
	}
	return signaturesErr
}

func (c *VerifiableCredential) Verify(options ...*VerifyOption) error {
	if c.Proof == nil && c.signature == nil {
		return errors.New("verifiableCredential does neither have a signature nor a proof")
	}
	vO := &verifyOptions{}

	if options != nil {
		for _, o := range options {
			if o != nil {
				err := o.apply(vO)
				if err != nil {
					return err
				}
			}
		}
	}

	if c.signature != nil {
		//make sure did is still valid
		web, err := did.ResolveDIDWeb(c.signature.DID.Id)
		if err != nil {
			return err
		}
		err = web.ResolveMethods()
		if err != nil {
			return err
		}
		c.signature.DID = web

		key, k := c.signature.DID.Keys[c.signature.JWTHeader.KID]
		if !k {
			return errors.New("the KID from the JWT header does not match any key from the issuer DID")
		}
		cert, err := VerifyCertChain(key.JWK.X509URL())
		if err != nil {
			return err
		}

		host, err := c.signature.DID.GetHost()
		if err != nil {
			return err
		}
		if !slices.Contains(cert.DNSNames, host) {
			return fmt.Errorf("host %v not in the list of allowed DNS Names %v of the provided DID x509 certificate", host, cert.DNSNames)
		}

		_, err = jws.Verify(c.signature.OriginalJWT, jws.WithKey(c.signature.JWTHeader.Algorithm, key.JWK))
		if err != nil {
			return fmt.Errorf("verifiableCredential signature is invalid: %w", err)
		}

		if !(c.signature.JWTHeader.TYP == JWTType || c.signature.JWTHeader.TYP == "vc+jwt") {
			return fmt.Errorf("verifiableCredential signature header does not have the correct type of JWT")
		}

		if !(c.signature.JWTHeader.CTY == JWTCTY || c.signature.JWTHeader.CTY == "vc") {
			return fmt.Errorf("verifiableCredential signature header does not have the correct cty")
		}

		now := time.Now()

		if now.UnixMilli() < c.signature.JWTHeader.IAT.UnixMilli() {
			return fmt.Errorf("verifiableCredential issuance date is in the future")
		}
		if now.UnixMilli() > c.signature.JWTHeader.EXP.UnixMilli() {
			return fmt.Errorf("verifiableCredential not valid anymore")
		}

		if !c.ValidUntil.IsZero() {
			if !c.ValidUntil.After(now) {
				return fmt.Errorf("verifiableCredential is expired")
			}
		}

		if !c.ValidFrom.IsZero() {
			if c.ValidFrom.After(now) {
				return fmt.Errorf("verifiableCredential is not valid yet")
			}
		}

		if vO.issuerMatch {
			if c.Issuer != c.signature.JWTHeader.Issuer {
				return fmt.Errorf("credential issuer does not match JTW issuer")
			}
		}

		if vO.isTrustedIssuer {
			get, err := http.Get("https://gx-registry.gxdch.dih.telekom.com/v2/api/trusted-issuers")
			if err != nil {
				return err
			}
			defer func(Body io.ReadCloser) {
				_ = Body.Close()
			}(get.Body)
			all, err := io.ReadAll(get.Body)
			if err != nil {
				return err
			}

			if !(strings.Contains(string(all), host+"/v1") || strings.Contains(string(all), host+"/v2")) {
				return errors.New("is not a trusted gx issuer")
			}
		}

		return nil
	}

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

		p := c.Proof

		c.Proof = nil

		n, err := c.CanonizeGo()
		if err != nil {
			c.Proof = p
			c.mux.Unlock()
			return err
		}
		c.Proof = p
		c.mux.Unlock()

		var pn []byte

		if !vO.useOldSignature {
			pn, err = proof.Normalize(c)
			if err != nil {
				return err
			}
		}

		sdHash := GenerateHash(n)
		var proofHash []byte
		if len(pn) > 0 {
			proofHash = GenerateHash(pn)
		}

		key, ok := d.Keys[proof.VerificationMethod]
		if !ok {
			return fmt.Errorf("verfication method not defined in DID")
		}
		if !slices.Contains(key.AllowedMethods, did.AssertionMethod) {
			return fmt.Errorf("verfication method %v not allowed as %v", proof.VerificationMethod, did.AssertionMethod)
		}

		k := key.JWK

		_, err = VerifyCertChain(k.X509URL())
		if err != nil {
			log.Println(err)
		}

		var hash []byte

		if vO.useOldSignature {
			hash = []byte(EncodeToString(sdHash))
		} else {
			hash = bytes.Join([][]byte{proofHash, sdHash}, []byte{})
		}

		_, err = jws.Verify([]byte(proof.JWS), jws.WithKey(k.Algorithm(), k), jws.WithDetachedPayload(hash))
		if err != nil {
			if !vO.retryWithOldSignature {
				options = append(options, retryWithOldSignAlgorithm())
				return c.Verify(options...)
			}
			return err
		}

		return nil
	}
	return errors.New("has no proof")
}

func (c *VerifiableCredential) setupJsonLdProcessor() {
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

func (c *VerifiableCredential) CanonizeGo() ([]byte, error) {
	m, err := c.ToMap()
	if err != nil {
		return nil, err
	}

	c.once.Do(c.setupJsonLdProcessor)

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

func (c *VerifiableCredential) Expand() ([][]byte, error) {
	m, err := c.ToMap()
	if err != nil {
		return nil, err
	}

	c.once.Do(c.setupJsonLdProcessor)

	options := ld.NewJsonLdOptions("")

	options.Explicit = true

	n, err := c.proc.Expand(m, options)
	if err != nil {
		if strings.Contains(err.Error(), string(ld.LoadingRemoteContextFailed)) {
			log.Println(err.Error())
		}
		return nil, fmt.Errorf("jsongold error: %v", err)
	}

	l := make([][]byte, len(n))

	for i, ele := range n {
		marshal, err := json.Marshal(ele)
		if err != nil {
			return nil, err
		}
		l[i] = marshal
	}
	return l, nil
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

func (c *VerifiableCredential) HashHex() (string, error) {
	jsc, err := c.JSC()
	if err != nil {
		return "", err
	}
	hash := GenerateHash(jsc)
	return EncodeToString(hash), nil
}

func (c *VerifiableCredential) String() string {
	marshal, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return ""
	}
	return string(marshal)
}

func (c *VerifiableCredential) AddToCredentialSubject(obj any) error {
	m, err := toMap(obj)
	if err != nil {
		return err
	}
	c.CredentialSubject.CredentialSubject = append(c.CredentialSubject.CredentialSubject, m)
	return nil
}

type Namespace struct {
	Namespace string
	URL       string
}

func (c *Namespace) MarshalJSON() ([]byte, error) {
	if c.Namespace == "" {
		return json.Marshal(c.URL)
	}
	return json.Marshal(c)
}

type Context struct {
	Context  []Namespace
	wasSlice bool
}

func (c *Context) MarshalJSON() ([]byte, error) {
	if len(c.Context) == 1 && !c.wasSlice {
		if c.Context[0].Namespace == "" {
			return json.Marshal(c.Context[0].URL)
		}
		return json.Marshal(c.Context[0])
	}
	var x []interface{}

	for _, i := range c.Context {
		if i.Namespace == "" {
			x = append(x, i.URL)
		} else {
			x = append(x, i)
		}
	}
	b, err := json.Marshal(x)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (c *Context) UnmarshalJSON(dat []byte) error {
	var ns []Namespace
	err := json.Unmarshal(dat, &ns)
	if err != nil {
		ns = ns[:0]
		var co string
		err = json.Unmarshal(dat, &co)
		if err != nil {
			var nss []interface{}
			err = json.Unmarshal(dat, &nss)
			if err != nil {
				return err
			}
			for _, ele := range nss {
				n, k := ele.(map[string]string)
				if k {
					for k, e := range n {
						ns = append(ns, Namespace{
							Namespace: k,
							URL:       e,
						})
					}

				}
				s, k := ele.(string)
				if k {
					ns = append(ns, Namespace{
						Namespace: "",
						URL:       s,
					})
				} else {
					return errors.New("context not correctly defined")
				}
			}
			c.Context = ns
			c.wasSlice = true

			return nil
		}
		ns = append(ns, Namespace{
			Namespace: "",
			URL:       co,
		})
		c.Context = ns
		c.wasSlice = false
	} else {
		c.Context = ns
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

func (p *Proof) Normalize(vc *VerifiableCredential) ([]byte, error) {
	pm, err := p.ToMap()
	if err != nil {
		return nil, err
	}
	delete(pm, "jws")

	pm["@context"] = []interface{}{
		"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/security/suites/jws-2020/v1",
	}

	vc.once.Do(vc.setupJsonLdProcessor)

	n, err := vc.proc.Normalize(pm, vc.Options)
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

func (p *Proof) ToMap() (map[string]interface{}, error) {
	marshal, err := json.Marshal(p)
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

type VerifyOption struct {
	f func(option *verifyOptions) error
}

func (so *VerifyOption) apply(option *verifyOptions) error {
	return so.f(option)
}

// verifyOptions is an internal struct to store the various options
type verifyOptions struct {
	useOldSignature       bool
	retryWithOldSignature bool
	mux                   sync.RWMutex
	isTrustedIssuer       bool
	issuerMatch           bool
	notary                string
}

func UseOldSignAlgorithm() *VerifyOption {
	return &VerifyOption{f: func(option *verifyOptions) error {
		option.useOldSignature = true
		return nil
	}}
}

func IsGaiaXTrustedIssuer(notary string) *VerifyOption {
	return &VerifyOption{f: func(option *verifyOptions) error {
		if notary == "" {
			notary = "https://gx-registry.gxdch.dih.telekom.com/v2/api/trusted-issuers"
		}
		option.isTrustedIssuer = true
		return nil
	}}
}

func IssuerMatch() *VerifyOption {
	return &VerifyOption{f: func(option *verifyOptions) error {
		option.isTrustedIssuer = true
		return nil
	}}
}

func retryWithOldSignAlgorithm() *VerifyOption {
	return &VerifyOption{f: func(option *verifyOptions) error {
		option.useOldSignature = true
		option.retryWithOldSignature = true
		return nil
	}}
}

type UnixTimeMilli struct {
	time.Time
}

func (t *UnixTimeMilli) UnmarshalJSON(dat []byte) error {
	var ts int64
	err := json.Unmarshal(dat, &ts)
	if err != nil {
		return err
	}
	t.Time = time.UnixMilli(ts)
	return nil
}

type JWTHeader struct {
	Algorithm jwa.SignatureAlgorithm `json:"alg"`
	Issuer    string                 `json:"iss"`
	KID       string                 `json:"kid"`
	IAT       UnixTimeMilli          `json:"iat,omitempty,omitzero"`
	EXP       UnixTimeMilli          `json:"exp,omitempty,omitzero"`
	CTY       string                 `json:"cty"`
	TYP       string                 `json:"typ"`
}

func EncodeToString(hash []byte) string {
	return hex.EncodeToString(hash[:])
}

func GenerateHash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

type CredentialSubjectShape struct {
	ID string `json:"@id,omitempty"`
	// option to provide Types
	Type string `json:"@type,omitempty,omitzero"`
}
