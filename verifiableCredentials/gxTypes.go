/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package verifiableCredentials

import (
	"encoding/json"
)

// RegistrationNumber2210Struct implements the shape of the registry number see:
// https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#gx:legalRegistrationNumberShape
type RegistrationNumber2210Struct struct {
	Context                         Context `json:"@context"`
	Type                            string  `json:"type"`
	ID                              string  `json:"id"`
	GxVatID                         string  `json:"gx:vatID,omitempty"`
	GXVATCountryCode                string  `json:"gx:vatID-countryCode,omitempty"`
	GxLeiCode                       string  `json:"gx:leiCode,omitempty"`
	GxLeiCodeCountryCode            string  `json:"gx:leiCode-countryCode,omitempty"`
	GxLeiCodeSubdivisionCountryCode string  `json:"gx:leiCode-subdivisionCountryCode,omitempty"`
	GXTaxID                         string  `json:"gx:taxID,omitempty"`
	GXEUID                          string  `json:"gx:EUID,omitempty"`
	GXEORI                          string  `json:"gx:EORI,omitempty"`
}

// TermsAndConditions2210Struct implements the shape of the terms and conditions see:
// https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#gx:GaiaXTermsAndConditionsShape
type TermsAndConditions2210Struct struct {
	Context              Context `json:"@context"`
	Type                 string  `json:"type"`
	GxTermsAndConditions string  `json:"gx:termsAndConditions"`
	ID                   string  `json:"id"`
}

func (tc *TermsAndConditions2210Struct) ToMap() (map[string]interface{}, error) {
	j, err := json.Marshal(tc)
	if err != nil {
		return nil, err
	}

	var m = map[string]interface{}{}
	err = json.Unmarshal(j, &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// ComplianceCredentialSubject implements the shape as returned by the compliance service as compliance credentials
type ComplianceCredentialSubject struct {
	Type                     string `json:"type"`
	ID                       string `json:"id"`
	GxIntegrity              string `json:"gx:integrity"`
	GxIntegrityNormalization string `json:"gx:integrityNormalization"`
	GxVersion                string `json:"gx:version"`
	GxType                   string `json:"gx:type"`
}

// NewComplianceCredentialSubjectFormMap marshals a map to ComplianceCredentialSubject or returns an error
func NewComplianceCredentialSubjectFormMap(c map[string]interface{}) (*ComplianceCredentialSubject, error) {
	marshal, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	ccs := &ComplianceCredentialSubject{}
	err = json.Unmarshal(marshal, ccs)
	if err != nil {
		return nil, err
	}
	return ccs, nil
}
