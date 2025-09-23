/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package verifiableCredentials

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

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

const GXISOTimeFormat = "2006-01-02T15:04:05.999-07:00"

type JTime struct {
	time.Time
}

func (t JTime) MarshalJSON() ([]byte, error) {
	s := fmt.Sprintf("\"%s\"", t.Format(GXISOTimeFormat))
	h := strings.Split(s, ".")
	h1 := strings.Split(h[1], "+")
	if len(h1[0]) != 3 {
		s = h[0] + "." + h1[0] + "0" + "+" + h1[1]
		s = fmt.Sprintf("%s", s)
	}
	return []byte(s), nil
}

func (t *JTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), "\"")
	ti, err := time.Parse(GXISOTimeFormat, s)
	if err != nil {
		ti, err = time.Parse("2006-01-02T15:04:05.999Z07:00", s)
		if err != nil {
			return err
		}
	}
	t.Time = ti
	return nil
}

// VerifiablePresentation implements the shape of a verifiable presentation as defined in: https://www.w3.org/TR/vc-data-model/#presentations
// since Gaia-X has not defined a proof method yet, this is still open
type VerifiablePresentation struct {
	Context              Context                 `json:"@context" validate:"required"`
	Id                   string                  `json:"id,omitempty,omitzero"`
	Type                 string                  `json:"type" validate:"required"`
	VerifiableCredential []*VerifiableCredential `json:"verifiableCredential" validate:"required"`
	Proof                *Proofs                 `json:"proof,omitempty"`                                //non-standard-compliant
	Issuer               string                  `json:"issuer,omitempty,omitzero" validate:"omitempty"` //non-standard-compliant
	ValidFrom            JTime                   `json:"validFrom,omitzero" validate:"omitempty"`        //non-standard-compliant
	ValidUntil           JTime                   `json:"validUntil,omitzero" validate:"omitempty"`       //non-standard-compliant
	Holder               any                     `json:"holder,omitempty,omitzero" validate:"omitempty"`
	signature            *JWSSignature
	decodedCredentials   []*VerifiableCredential
	proc                 *ld.JsonLdProcessor
	Options              *ld.JsonLdOptions `json:"-"`
	mux                  sync.Mutex
	once                 sync.Once
}

func NewEmptyVerifiablePresentation() *VerifiablePresentation {
	return &VerifiablePresentation{
		Context: Context{
			Context:  []Namespace{W3Credentials},
			wasSlice: true,
		},
		Type:                 "VerifiablePresentation",
		VerifiableCredential: make([]*VerifiableCredential, 0),
		Proof:                nil,
	}
}

func NewEmptyVerifiablePresentationV2() *VerifiablePresentation {
	return &VerifiablePresentation{
		Context: Context{
			Context:  []Namespace{W3CredentialsV2},
			wasSlice: true,
		},
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

	/* TODO caching
	if len(vp.VerifiableCredential) == len(vp.decodedCredentials) {
		return vp.decodedCredentials, nil
	}


	*/
	vp.decodedCredentials = make([]*VerifiableCredential, len(vp.VerifiableCredential))
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
			if err != nil {
				return nil, err
			}
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

func (vp *VerifiablePresentation) DecodeCredentialsToResolvedCSMap() (map[string]map[string]interface{}, error) {
	csMap := make(map[string]map[string]interface{})

	if vp.decodedCredentials == nil {
		_, err := vp.DecodeEnvelopedCredentials()
		if err != nil {
			return nil, err
		}
	}

	for i, v := range vp.decodedCredentials {
		for _, cs := range v.CredentialSubject.CredentialSubject {
			var id string
			var ok bool
			if idi, k := cs["id"]; k {
				id, ok = idi.(string)
				if !ok {
					return nil, fmt.Errorf("invalid credential subject id at index: %v", v.ID)
				}
			} else if idi, k := cs["@id"]; k {
				id, ok = idi.(string)
				if !ok {
					return nil, fmt.Errorf("invalid credential subject id at index: %v", v.ID)
				}
			} else {
				id = "" //todo this is a privacy preserving vs how to handle?
				if v.ID != "" {
					id = v.ID + "#" + string(rune(i))
				}
			}
			if id != "" {
				if _, k := cs["type"]; !k {
					for _, ty := range v.Type.Types {
						if ty != "VerifiableCredential" {
							cs["type"] = ty
							break
						}
					}
				}
				csMap[id] = cs
			}
		}
	}

	for i, cs := range csMap {
		k := Resolve(cs, csMap)
		if m, ok := k.(map[string]interface{}); ok {
			csMap[i] = m
		}
	}
	return csMap, nil
}

type vcMap struct {
	vc    *VerifiableCredential
	csIDs []string
}

func (vp *VerifiablePresentation) DecodeCredentialsAndResolveAllReferences() ([]*VerifiableCredential, error) {
	csMap := make(map[string]map[string]interface{})

	if vp.decodedCredentials == nil {
		_, err := vp.DecodeEnvelopedCredentials()
		if err != nil {
			return nil, err
		}
	}

	vcm := make(map[string]vcMap, len(vp.VerifiableCredential))

	for _, v := range vp.decodedCredentials {
		jv, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		vc := &VerifiableCredential{}
		err = json.Unmarshal(jv, &vc)
		if err != nil {
			return nil, err
		}
		vcm[vc.ID] = vcMap{
			vc:    vc,
			csIDs: []string{},
		}
	}

	for _, v := range vcm {
		for _, cs := range v.vc.CredentialSubject.CredentialSubject {
			var id string
			var ok bool
			if idi, k := cs["id"]; k {
				id, ok = idi.(string)
				if !ok {
					return nil, fmt.Errorf("invalid credential subject id at index: %v", v.vc.ID)
				}
			} else if idi, k := cs["@id"]; k {
				id, ok = idi.(string)
				if !ok {
					return nil, fmt.Errorf("invalid credential subject id at index: %v", v.vc.ID)
				}
			} else {
				id = "" //todo this is a privacy preserving vs how to handle?
				if v.vc.ID != "" {
					id = v.vc.ID + "#privacy"
				}
			}
			if id != "" {
				if _, k := cs["type"]; !k {
					for _, ty := range v.vc.Type.Types {
						if ty != "VerifiableCredential" {
							if ele, k := cs["type"]; k {
								switch e := ele.(type) {
								case string:
									n := []any{e, id}
									cs["type"] = n
								case []any:
									e = append(e, id)
									cs["type"] = e
								}
							} else {
								cs["type"] = ty
							}
						}
					}
				}
				csMap[id] = cs
				if ele, ok := vcm[v.vc.ID]; ok {
					ele.csIDs = append(ele.csIDs, id)
					vcm[v.vc.ID] = ele
				}

			}
		}
	}

	for i, cs := range csMap {
		k := Resolve(cs, csMap)
		if m, ok := k.(map[string]interface{}); ok {
			csMap[i] = m
		}
	}
	var reVC []*VerifiableCredential
	for _, m := range vcm {
		if m.vc != nil {
			m.vc.CredentialSubject.CredentialSubject = []map[string]interface{}{}
			for _, id := range m.csIDs {
				m.vc.CredentialSubject.CredentialSubject = append(m.vc.CredentialSubject.CredentialSubject, csMap[id])
				reVC = append(reVC, m.vc)
			}
		}
	}
	return reVC, nil
}

func Resolve(in any, csMap map[string]map[string]interface{}) any {
	switch t := in.(type) {
	case map[string]interface{}:
		if len(t) == 1 {
			var i any
			var ok bool
			if i, ok = t["@id"]; !ok {
				if i, ok = t["id"]; !ok {
					return t
				}
			}
			if is, ok := i.(string); ok {
				return csMap[is]
			}
		} else if len(t) == 2 {
			var i any
			var ok bool
			if i, ok = t["@id"]; !ok {
				if i, ok = t["id"]; !ok {
					for id, ele := range t {
						t[id] = Resolve(ele, csMap)
					}
					return t
				}
			}
			if is, ok := i.(string); ok {
				var ty any
				if ty, ok = t["@type"]; !ok {
					if ty, ok = t["type"]; !ok {
						return t
					}
				}
				if ty != "" {
					return csMap[is]
				} else {
					return t
				}
			}
		} else {
			for id, ele := range t {
				t[id] = Resolve(ele, csMap)
			}
			return t
		}
	case []any:
		for i, ele := range t {
			t[i] = Resolve(ele, csMap)
		}
		return t
	}
	return in
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

func (vp *VerifiablePresentation) AddSignature(originalJWS []byte) error {
	didweb, header, payload, err := VerifyJWS(originalJWS)
	if err != nil {
		return err
	}
	vc := &VerifiableCredential{}

	err = json.Unmarshal(payload, vc)
	if err != nil {
		return err
	}
	vp.signature = &JWSSignature{
		OriginalJWT: originalJWS,
		DID:         didweb,
		JWTHeader:   header,
	}

	return nil

}

func (vp *VerifiablePresentation) GetOriginalJWS() []byte {
	if vp.signature != nil {
		return vp.signature.OriginalJWT
	}
	return nil
}

func (vp *VerifiablePresentation) Verify(options ...*verifyOption) error {
	if vp.signature == nil {
		return fmt.Errorf("verifiablePresentation is missing signature")
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

	//make sure did is still valid
	web, err := did.ResolveDIDWeb(vp.signature.DID.Id)
	if err != nil {
		return err
	}
	err = web.ResolveMethods()
	if err != nil {
		return err
	}
	vp.signature.DID = web

	key, k := vp.signature.DID.Keys[vp.signature.JWTHeader.KID]
	if !k {
		return errors.New("the KID from the JWT header does not match any key from the issuer DID")
	}

	cert, err := VerifyCertChain(key.JWK.X509URL())
	if err != nil {
		return err
	}

	host, err := vp.signature.DID.GetHost()
	if err != nil {
		return err
	}
	if !slices.Contains(cert.DNSNames, host) {
		return fmt.Errorf("host %v not in the list of allowed DNS Names %v of the provided DID x509 certificate", host, cert.DNSNames)
	}

	_, err = jws.Verify(vp.signature.OriginalJWT, jws.WithKey(vp.signature.JWTHeader.Algorithm, key.JWK))
	if err != nil {
		return fmt.Errorf("verifiablePresentation signature is invalid: %w", err)
	}

	if !(vp.signature.JWTHeader.TYP == JWTType || vp.signature.JWTHeader.TYP == "vp+jwt") {
		return fmt.Errorf("verifiablePresentation signature header does not have the correct type of JWT")
	}

	if !(vp.signature.JWTHeader.CTY == JWTCTY || vp.signature.JWTHeader.CTY == "vp") {
		return fmt.Errorf("verifiablePresentation signature header does not have the correct cty")
	}

	now := time.Now()

	if now.UnixMilli() < vp.signature.JWTHeader.IAT.UnixMilli() && vp.signature.JWTHeader.EXP.UnixMilli() > 0 {
		return fmt.Errorf("verifiablePresentation issuance date is in the future")
	}
	if now.UnixMilli() > vp.signature.JWTHeader.EXP.UnixMilli() && vp.signature.JWTHeader.EXP.UnixMilli() > 0 {
		return fmt.Errorf("verifiablePresentation not valid anymore")
	}

	if !vp.ValidUntil.IsZero() {
		if !vp.ValidUntil.After(now) {
			return fmt.Errorf("verifiablePresentation is expired")
		}
	}

	if !vp.ValidFrom.IsZero() {
		if vp.ValidFrom.After(now) {
			return fmt.Errorf("verifiablePresentation is not valid yet")
		}
	}

	if vO.issuerMatch {
		if vp.Issuer != vp.signature.JWTHeader.Issuer {
			log.Printf("verifiablePresentation is not valid %v %v", vp.Issuer, vp.signature.JWTHeader.Issuer)
			return fmt.Errorf("verifialePresentation issuer does not match JWT issuer")
		}
	}

	if vO.isTrustedIssuer {
		get, err := http.Get(vO.trustedIssuerUrl)
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
		if get.StatusCode != 200 {
			return fmt.Errorf("unexpected status code from trustedIssuerUrl server: %v", string(all))
		}
		if !(strings.Contains(string(all), host)) {
			return errors.New("is not a trusted gx issuer")
		}
	}

	return nil
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
			vc.ValidFrom = JTime{time.Now()}
			return nil
		},
	}
}

func WithValidUntil(t time.Time) VerifiableCredentialOption {
	return &baseVCOption{
		f: func(vc *VerifiableCredential) error {
			if !vc.ValidUntil.IsZero() {
				return errors.New("validUntil already set")
			}
			vc.ValidUntil = JTime{t}
			return nil
		},
	}
}

func WithValidFor(t time.Duration) VerifiableCredentialOption {
	return &baseVCOption{
		f: func(vc *VerifiableCredential) error {
			if !vc.ValidUntil.IsZero() {
				return errors.New("validUntil already set")
			}
			vc.ValidUntil = JTime{time.Now().Add(t)}
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
// updated to https://www.w3.org/TR/vc-data-model-2.0/#verifiable-credentials with version 0.2.9
type VerifiableCredential struct {
	Context           Context           `json:"@context" validate:"required"`
	ID                string            `json:"id" validate:"required"`
	Type              VCType            `json:"type" validate:"required"`
	Name              string            `json:"name,omitempty" validate:"omitempty"`
	Description       string            `json:"description,omitempty" validate:"omitempty"`
	Issuer            string            `json:"issuer,omitzero" validate:"omitempty"`
	CredentialSubject CredentialSubject `json:"credentialSubject,omitempty,omitzero" validate:"omitempty"`
	ValidFrom         JTime             `json:"validFrom,omitzero" validate:"omitempty"`
	ValidUntil        JTime             `json:"validUntil,omitzero" validate:"omitempty"`
	CredentialsStatus any               `json:"credentialStatus,omitempty" validate:"omitempty"`
	CredentialSchema  any               `json:"credentialSchema,omitempty" validate:"omitempty"`
	RefreshService    any               `json:"refreshService,omitempty" validate:"omitempty"`
	TermsOfUse        any               `json:"termsOfUse,omitempty" validate:"omitempty"`
	IssuanceDate      string            `json:"issuanceDate,omitempty,omitzero" validate:"omitempty"` //non-standard
	ExpirationDate    string            `json:"expirationDate,omitempty,omitzero"`                    //non-standard
	Proof             *Proofs           `json:"proof,omitempty"`
	Evidence          any               `json:"evidence,omitempty"`
	proc              *ld.JsonLdProcessor
	Options           *ld.JsonLdOptions `json:"-"`
	mux               sync.Mutex
	once              sync.Once
	signature         *JWSSignature
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
	didweb, header, payload, err := VerifyJWS(originalJWS)
	if err != nil {
		return err
	}

	vc := &VerifiableCredential{}

	err = json.Unmarshal(payload, vc)
	if err != nil {
		return err
	}
	c.signature = &JWSSignature{
		OriginalJWT: originalJWS,
		DID:         didweb,
		JWTHeader:   header,
	}

	return nil

}

func (c *VerifiableCredential) Verify(options ...*verifyOption) error {
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

		if key.JWK.Algorithm() != c.signature.JWTHeader.Algorithm {
			return fmt.Errorf("alg in jws %v does not match alg in did %v", c.signature.JWTHeader.Algorithm, key.JWK.Algorithm())
		}

		cert, err := VerifyCertChain(key.JWK.X509URL())
		if err != nil {
			return err
		}

		host, err := c.signature.DID.GetHost()
		if err != nil {
			return err
		}

		certKey, err := jwk.FromRaw(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("error on parsing JWK public key: %v", err)
		}

		certMap, err := certKey.AsMap(context.Background())
		if err != nil {
			return err
		}

		keyMap, err := key.JWK.AsMap(context.Background())
		if err != nil {
			return err
		}

		certN, ok := certMap["n"].([]uint8)
		if !ok {
			return errors.New("missing key in certificate")
		}
		keyN, ok := keyMap["n"].([]uint8)
		if !ok {
			return errors.New("missing key in jwk")
		}

		if base64.StdEncoding.EncodeToString(certN) != base64.StdEncoding.EncodeToString(keyN) {
			return errors.New("mismatched public key in certificate and did jwk")
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

		if now.Unix() < c.signature.JWTHeader.IAT.Unix() && c.signature.JWTHeader.EXP.Unix() > 0 {
			return fmt.Errorf("verifiableCredential issuance date is in the future %v %v", now.Format(time.RFC3339Nano), c.signature.JWTHeader.IAT.Format(time.RFC3339Nano))
		}
		if now.Unix() > c.signature.JWTHeader.EXP.Unix() && c.signature.JWTHeader.EXP.Unix() > 0 {
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
				return fmt.Errorf("credential issuer does not match JWT issuer")
			}
		}

		if vO.isTrustedIssuer {
			get, err := http.Get(vO.trustedIssuerUrl)
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
			if get.StatusCode != 200 {
				return fmt.Errorf("unexpected status code from trustedIssuerUrl server: %v", string(all))
			}
			if !(strings.Contains(string(all), host)) {
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
	ns := map[string]string{c.Namespace: c.URL}
	return json.Marshal(ns)
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
	b, err := json.Marshal(c.Context)
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
				switch v := ele.(type) {
				case string:
					ns = append(ns, Namespace{
						Namespace: "",
						URL:       v,
					})
				case map[string]interface{}:
					if len(v) > 1 {
						return errors.New("context not correctly defined")
					}
					for k, e := range v {
						u, ok := e.(string)
						if !ok {
							return errors.New("context not correctly defined")
						}
						ns = append(ns, Namespace{
							Namespace: k,
							URL:       u,
						})
					}
				default:
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

type verifyOption struct {
	f func(option *verifyOptions) error
}

func (so *verifyOption) apply(option *verifyOptions) error {
	return so.f(option)
}

// verifyOptions is an internal struct to store the various options
type verifyOptions struct {
	useOldSignature       bool
	retryWithOldSignature bool
	mux                   sync.RWMutex
	isTrustedIssuer       bool
	issuerMatch           bool
	trustedIssuerUrl      string
}

func UseOldSignAlgorithm() *verifyOption {
	return &verifyOption{f: func(option *verifyOptions) error {
		option.useOldSignature = true
		return nil
	}}
}

func IsGaiaXTrustedIssuer(trustedIssuerUrl string) *verifyOption {
	return &verifyOption{f: func(option *verifyOptions) error {
		if trustedIssuerUrl == "" {
			option.trustedIssuerUrl = "https://gx-registry.gxdch.dih.telekom.com/v2/api/trusted-issuers"
		} else {
			option.trustedIssuerUrl = trustedIssuerUrl
		}
		option.isTrustedIssuer = true
		return nil
	}}
}

func IssuerMatch() *verifyOption {
	return &verifyOption{f: func(option *verifyOptions) error {
		option.issuerMatch = true
		return nil
	}}
}

func retryWithOldSignAlgorithm() *verifyOption {
	return &verifyOption{f: func(option *verifyOptions) error {
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
	ID     string `json:"id,omitempty"`
	Type   string `json:"type,omitempty,omitempty"`
	AtType string `json:"@type,omitempty,omitempty"`
	AtID   string `json:"@id,omitempty"`
}
