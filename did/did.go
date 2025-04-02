/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package did

import (
	"encoding/json"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"strings"
)

/*
DID Document properties as defined in https://www.w3.org/TR/did-core/#did-document-properties
*/

var UniResolverURL = "https://resolver.lab.gaia-x.eu/1.0/identifiers/"

type DID struct {
	Id                   string               `json:"id"`                             //A string that conforms to the rules in 3.1 DID Syntax.
	AlsoKnownAs          []string             `json:"alsoKnownAs,omitempty"`          //A set of strings that conform to the rules of [RFC3986] for URIs.
	Controller           Controller           `json:"controller,omitempty"`           //A string or a set of strings that conform to the rules in 3.1 DID Syntax.
	VerificationMethod   []VerificationMethod `json:"verificationMethod,omitempty"`   //A set of Verification Method maps that conform to the rules in Verification Method properties.
	Authentication       VerificationMethods  `json:"authentication,omitempty"`       //A set of either Verification Method maps that conform to the rules in Verification Method properties or strings that conform to the rules in 3.2 DID URL Syntax.
	AssertionMethod      VerificationMethods  `json:"assertionMethod,omitempty"`      //A set of either Verification Method maps that conform to the rules in Verification Method properties or strings that conform to the rules in 3.2 DID URL Syntax.
	KeyAgreement         VerificationMethods  `json:"keyAgreement,omitempty"`         //A set of either Verification Method maps that conform to the rules in Verification Method properties or strings that conform to the rules in 3.2 DID URL Syntax.
	CapabilityInvocation VerificationMethods  `json:"capabilityInvocation,omitempty"` //A set of either Verification Method maps that conform to the rules in Verification Method properties or strings that conform to the rules in 3.2 DID URL Syntax.
	CapabilityDelegation VerificationMethods  `json:"capabilityDelegation,omitempty"` //A set of either Verification Method maps that conform to the rules in Verification Method properties or strings that conform to the rules in 3.2 DID URL Syntax.
	Service              []Service            `json:"service,omitempty"`              //A set of Service Endpoint maps that conform to the rules in Service properties.
	Context              []string             `json:"@context"`
	Keys                 map[string]*Key      `json:"-"` //not json marshal
}

func NewDID(id string) *DID {
	return &DID{
		Id: id,
		Context: []string{"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
	}
}

func (did *DID) ResolveMethods() error {
	did.Keys = make(map[string]*Key)
	for _, vm := range did.VerificationMethod {
		if vm.PublicKeyJwk != nil {
			pk := vm.PublicKeyJwk
			rawJWK, err := json.Marshal(pk)
			if err != nil {
				return err
			}
			key, err := jwk.ParseKey(rawJWK)
			if err != nil {
				return err
			}
			did.Keys[vm.Id] = &Key{
				JWK:            key,
				AllowedMethods: make([]Method, 0),
			}
		}
	}
	err := did.resolveJWK(did.AssertionMethod, AssertionMethod)
	if err != nil {
		return err
	}
	err = did.resolveJWK(did.Authentication, Authentication)
	if err != nil {
		return err
	}
	err = did.resolveJWK(did.CapabilityDelegation, CapabilityDelegation)
	if err != nil {
		return err
	}
	err = did.resolveJWK(did.CapabilityInvocation, CapabilityInvocation)
	if err != nil {
		return err
	}
	err = did.resolveJWK(did.KeyAgreement, KeyAgreement)
	if err != nil {
		return err
	}

	return nil
}

func (did *DID) GetHost() (string, error) {
	split := strings.Split(did.Id, ":")
	//verify
	if len(split) < 3 {
		return "", errors.New("did must contain a host name")
	}
	if split[0] != "did" {
		return "", errors.New("DID must start with 'did'")
	}
	if split[1] == "" {
		return "", errors.New("DID must include a method")
	}
	return split[2], nil
}

func (did *DID) resolveJWK(vms VerificationMethods, method Method) error {
	for _, vm := range vms {
		if vm.PublicKeyJwk != nil {
			pk := vm.PublicKeyJwk
			rawJWK, err := json.Marshal(pk)
			if err != nil {
				return err
			}
			key, err := jwk.ParseKey(rawJWK)
			if err != nil {
				return err
			}
			d, ok := did.Keys[vm.Id]
			if !ok {
				did.Keys[vm.Id] = &Key{
					JWK:            key,
					AllowedMethods: []Method{method},
				}
			} else {
				d.AllowedMethods = append(d.AllowedMethods, method)
			}
		} else if vm.PublicKeyMultibase != "" {
			/*
				not implemented see: https://www.w3.org/TR/did-core/#dfn-publickeymultibase
				Note that the [MULTIBASE] specification is not yet a standard and is subject to change. There might be some use cases for this data format where publicKeyMultibase is defined, to allow for expression of public keys, but privateKeyMultibase is not defined, to protect against accidental leakage of secret keys.
			*/
			continue
		} else {
			d, ok := did.Keys[vm.Id]
			if ok {
				d.AllowedMethods = append(d.AllowedMethods, method)
			}
		}
	}
	return nil
}

type Key struct {
	JWK            jwk.Key
	AllowedMethods []Method
}

// VerificationMethod as defined in https://www.w3.org/TR/did-core/#verification-method-properties
type VerificationMethod struct {
	Id                 string                 `json:"id"`
	Controller         string                 `json:"controller"`
	Type               string                 `json:"type"`
	PublicKeyJwk       map[string]interface{} `json:"publicKeyJwk,omitempty"` //json jwk representation
	PublicKeyMultibase string                 `json:"publicKeyMultibase,omitempty"`
}

type ServiceType string

var OID4VC ServiceType = "OID4VCI"
var OID4CP ServiceType = "OID4VP"
var LinkedDomain ServiceType = "LinkedDomains"
var DIDCommMessaging ServiceType = "DIDCommMessaging"
var CredentialRegistry ServiceType = "CredentialRegistry"

// Service as defined in https://www.w3.org/TR/did-core/#service-properties
// https://www.w3.org/TR/did-spec-registries/#openid4-verifiable-presentation
type Service struct {
	Id              string      `json:"id"`
	Type            ServiceType `json:"type"`
	ServiceEndpoint interface{} `json:"serviceEndpoint"`
	Accept          []string    `json:"accept,omitempty"`
	RoutingKeys     []string    `json:"routingKeys,omitempty"`
}

// Controller as defined in https://www.w3.org/TR/did-core/#dfn-controller
type Controller []string

// MarshalJSON is a custom implementation since the controller can be a list or a single value
func (c Controller) MarshalJSON() ([]byte, error) {
	if len(c) == 1 {
		b, err := json.Marshal(c[0])
		if err != nil {
			return nil, err
		}
		return b, nil
	} else {
		b, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		return b, nil
	}

}

// UnmarshalJSON is a custom implementation since the controller can be a list or a single value
func (c *Controller) UnmarshalJSON(dat []byte) error {
	var cs []string
	err := json.Unmarshal(dat, &cs)
	if err != nil {
		var co string
		err = json.Unmarshal(dat, &co)
		if err != nil {
			return err
		}
		*c = []string{co}
	} else {
		*c = cs
	}
	return nil
}

// VerificationMethods is used authentication, assertionMethod, keyAgreement, capabilityInvocation,capabilityDelegation for custom marshalling
type VerificationMethods []VerificationMethod

// MarshalJSON is a custom implementation since authentication, assertionMethod, keyAgreement, capabilityInvocation,capabilityDelegation can be a list or a single value
func (v VerificationMethods) MarshalJSON() ([]byte, error) {
	var x []interface{}
	for _, i := range v {
		if i.Controller == "" {
			x = append(x, i.Id)
		} else {
			x = append(x, i)
		}
	}
	b, err := json.Marshal(x)
	if err != nil {
		return nil, err
	}
	return b, err
}

// UnmarshalJSON is a custom implementation since authentication, assertionMethod, keyAgreement, capabilityInvocation,capabilityDelegation can be a list or a single value
func (v *VerificationMethods) UnmarshalJSON(dat []byte) error {
	var cs []VerificationMethod
	err := json.Unmarshal(dat, &cs)
	if err != nil {
		var id []string
		err = json.Unmarshal(dat, &id)
		if err != nil {
			var in []interface{}
			err = json.Unmarshal(dat, &in)
			if err != nil {
				return err
			}
			var c []VerificationMethod
			for _, i := range in {
				a, ok := i.(string)
				if !ok {
					a, ok := i.(map[string]interface{})
					if !ok {
						return errors.New("could not unmarshal json")
					}
					co := &VerificationMethod{}
					if uID, ok := a["id"]; ok {
						co.Id = uID.(string)
					}
					if uController, ok := a["controller"]; ok {
						co.Controller = uController.(string)
					}
					if uType, ok := a["type"]; ok {
						co.Type = uType.(string)
					}
					if uPublicKeyJwk, ok := a["publicKeyJwk"]; ok {
						co.PublicKeyJwk = uPublicKeyJwk.(map[string]interface{})
					}
					if uPublicKeyMultibase, ok := a["publicKeyMultibase"]; ok {
						co.PublicKeyMultibase = uPublicKeyMultibase.(string)
					}
					c = append(c, *co)
				} else {
					co := &VerificationMethod{
						Id: a,
					}
					c = append(c, *co)
				}
			}
			*v = c
		} else {
			var c []VerificationMethod
			for _, i := range id {
				co := &VerificationMethod{
					Id: i,
				}
				c = append(c, *co)

			}
			*v = c
		}
	} else {
		*v = cs
	}
	return nil
}

// Method implements the various methods in the verifiable credential
type Method string

const Authentication Method = "authentication"
const AssertionMethod Method = "assertionMethod"
const KeyAgreement Method = "keyAgreement"
const CapabilityInvocation Method = "capabilityInvocation"
const CapabilityDelegation Method = "capabilityDelegation"
