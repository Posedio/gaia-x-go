package signer

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Posedio/gaia-x-go/did"
	vcTypes "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

type Signer interface {
	SelfSign(credential *vcTypes.VerifiableCredential) error
	ReSelfSign(credential *vcTypes.VerifiableCredential) error
	SelfSignPresentation(presentation *vcTypes.VerifiablePresentation, validFor time.Duration) error
	SelfVerify(vc *vcTypes.VerifiableCredential) error
	SelfSignCredentialSubject(id string, credentialSubject []map[string]interface{}) (*vcTypes.VerifiableCredential, error)
	GetIssuer() string
	GetVerificationMethod() string
}

type IssuerSetting struct {
	Key                jwk.Key
	Alg                jwa.SignatureAlgorithm
	Issuer             string
	VerificationMethod string
}
type JWTSigner struct {
	Issuer *IssuerSetting
	Client *http.Client
}

// NewSigner returns ony a VP and VC signer without any gx dependencies
func NewSigner(issuer *IssuerSetting, opts ...option) (Signer, error) {
	opt := &options{}
	for _, o := range opts {
		if err := o.apply(opt); err != nil {
			return nil, err
		}
	}
	if opt.retryClient == nil {
		opt.retryClient = retryablehttp.NewClient()
		opt.retryClient.RetryMax = 2
		opt.retryClient.RetryWaitMin = 10 * time.Second
		opt.retryClient.RetryWaitMax = 60 * time.Second
		opt.retryClient.HTTPClient.Timeout = 90 * time.Second
		opt.retryClient.Logger = nil

		opt.retryClient.CheckRetry = vcTypes.DefaultRetryPolicy
	}

	rc := opt.retryClient.StandardClient()

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

	sig := &JWTSigner{
		Client: rc,
		Issuer: issuer,
	}

	return sig, nil
}

func (c *JWTSigner) GetIssuer() string {
	return c.Issuer.Issuer
}

func (c *JWTSigner) GetVerificationMethod() string {
	return c.Issuer.VerificationMethod
}

func (c *JWTSigner) SelfVerify(vc *vcTypes.VerifiableCredential) error {
	return vc.Verify()
}

// SelfSign adds a crypto proof to the self-description
func (c *JWTSigner) SelfSign(vc *vcTypes.VerifiableCredential) error {
	_, err := c.SelfSignVC(vc)
	return err
}

func (c *JWTSigner) ReSelfSign(credential *vcTypes.VerifiableCredential) error {
	credential.Proof = nil
	_, err := c.SelfSignVC(credential)
	return err
}

func (c *JWTSigner) SelfSignVC(vc *vcTypes.VerifiableCredential) (*vcTypes.VerifiableCredential, error) {
	if vc == nil {
		return nil, errors.New("vc can not be nil")
	}

	headers := jws.NewHeaders()
	err := headers.Set("alg", c.Issuer.Alg.String())
	if err != nil {
		return nil, err
	}
	err = headers.Set("iss", c.Issuer.Issuer)
	if err != nil {
		return nil, err
	}
	err = headers.Set("kid", c.Issuer.VerificationMethod)
	if err != nil {
		return nil, err
	}

	err = headers.Set("iat", time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}

	if !vc.ValidUntil.InternalTime.IsZero() {
		err = headers.Set("exp", vc.ValidUntil.InternalTime.UnixMilli())
		if err != nil {
			return nil, err
		}
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

	buf, err := jws.Sign(jsc, jws.WithKey(c.Issuer.Alg, c.Issuer.Key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, err
	}

	err = vc.AddSignature(buf)
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (c *JWTSigner) SelfSignCredentialSubject(id string, credentialSubject []map[string]interface{}) (*vcTypes.VerifiableCredential, error) {
	vc, err := vcTypes.NewEmptyVerifiableCredentialV2(
		vcTypes.WithVCID(id),
		vcTypes.WithValidFromNow(),
		vcTypes.WithIssuer(c.Issuer.Issuer),
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

func (c *JWTSigner) SelfSignPresentation(vp *vcTypes.VerifiablePresentation, validFor time.Duration) error {
	if vp == nil {
		return errors.New("vc can not be nil")
	}

	if vp.Issuer == "" {
		vp.Issuer = c.Issuer.Issuer
	}

	headers := jws.NewHeaders()
	err := headers.Set("alg", c.Issuer.Alg.String())
	if err != nil {
		return err
	}
	err = headers.Set("iss", c.Issuer.Issuer)
	if err != nil {
		return err
	}
	err = headers.Set("kid", c.Issuer.VerificationMethod)
	if err != nil {
		return err
	}
	err = headers.Set("iat", time.Now().UnixMilli())
	if err != nil {
		return err
	}

	if validFor != 0 {
		err = headers.Set("exp", time.Now().Add(validFor).UnixMilli())
		if err != nil {
			return err
		}
	}

	err = headers.Set("cty", "vp")
	if err != nil {
		return err
	}
	err = headers.Set("typ", "vp+jwt")
	if err != nil {
		return err
	}

	jsc, err := vp.ToJson()
	if err != nil {
		return err
	}

	buf, err := jws.Sign(jsc, jws.WithKey(c.Issuer.Alg, c.Issuer.Key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return err
	}

	err = vp.AddSignature(buf)
	if err != nil {
		return err
	}
	return nil
}

type options struct {
	retryClient *retryablehttp.Client
}

// option for future usage
type option struct {
	f func(option *options) error
}

func (so *option) apply(option *options) error {
	return so.f(option)
}

func CustomRetryClient(client *retryablehttp.Client) *option {
	return &option{f: func(option *options) error {
		option.retryClient = client
		return nil
	}}
}
