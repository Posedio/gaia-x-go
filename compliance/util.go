/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package compliance

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/Posedio/gaia-x-go/gxTypes"
	"github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/go-viper/mapstructure/v2"
)

// hash256 returns the sha256 hex representation of the given byte slice
func hash256(sd []byte) string {
	h := sha256.New()
	h.Write(sd)

	ha := h.Sum(nil)

	hash := fmt.Sprintf("%x", ha)
	return hash
}

func ValidateGXCompliance(vp *verifiableCredentials.VerifiablePresentation, complianceCredential *verifiableCredentials.VerifiableCredential) (any, error) {
	if vp == nil {
		return nil, errors.New("verifiableCredentials is nil")
	}
	if complianceCredential == nil {
		return nil, errors.New("complianceCredential is nil")
	}

	credentials, err := vp.DecodeEnvelopedCredentials()
	if err != nil {
		return nil, err
	}

	// make map of credentials
	mapping := make(map[string]*verifiableCredentials.VerifiableCredential, len(credentials))
	for _, credential := range credentials {
		mapping[credential.ID] = credential
	}

	if len(mapping) == 0 {
		return nil, errors.New("no verifiableCredentials in vp")
	}

	var LabelCredential gxTypes.LabelCredential

	err = mapstructure.Decode(complianceCredential.CredentialSubject.CredentialSubject[0], &LabelCredential)
	if err != nil {
		return nil, err
	}

	if len(LabelCredential.CompliantCredentials) == 0 {
		// try tagus
		var subjects []gxTypes.ComplianceCredentialSubject
		err = mapstructure.Decode(complianceCredential.CredentialSubject.CredentialSubject, &subjects)
		if err != nil {
			return nil, err
		}
		if len(subjects) == 0 {
			return nil, errors.New("no compliant credentials in compliance credential")
		}
		for _, subject := range subjects {
			if vc, ok := mapping[subject.ID]; ok {
				hex, err := vc.HashHex()
				if err != nil {
					return nil, err
				}
				if "sha256-"+hex != subject.GxIntegrity {
					return nil, fmt.Errorf("compliant credential hash does not match digest %v for vc", subject.ID)
				}
			} else {
				return nil, fmt.Errorf("verifiable credential with id %v not found", subject.ID)
			}
		}

		return subjects, nil
	}

	for _, compliantCredential := range LabelCredential.CompliantCredentials {
		if vc, ok := mapping[compliantCredential.Id]; ok {
			hex, err := vc.HashHex()
			if err != nil {
				return nil, err
			}
			if "sha256-"+hex != compliantCredential.DigestSRI {
				return nil, fmt.Errorf("compliant credential hash does not match digest %v for vc", compliantCredential.Id)
			}
		} else {
			return nil, fmt.Errorf("verifiable credential with id %v not found", compliantCredential.Id)
		}
	}
	return &LabelCredential, nil
}
