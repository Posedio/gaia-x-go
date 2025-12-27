/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package tagus

import (
	"testing"

	"github.com/Posedio/gaia-x-go/compliance"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

func TestSignTermsAndConditions(t *testing.T) {
	// at this point there is no way anymore to avoid a certificate with a qualified trust anchor.
	// for details how to load a certificate see the getKey function below

	// to accept the terms and conditions with YOUR digital identity first a compliance server has to be selected see compliance.ServiceUrl
	// version can stay on the 22.10 since is this is the most up-to-date version
	// there is no need for the legal registration number endpoint
	// as described above a private key with a public key that is signed by a qualified trust anchor is needed
	// as issuer a did as shown in 1_did is shown has to be provided
	// since a did can have multiple verification methods one that is used have to be specified, obviously this has to be the qualified public key to the set private key.
	connector, err := compliance.NewComplianceConnectorV2(
		compliance.Endpoints{
			Compliance: compliance.V1Staging,
			Notary:     compliance.DeltaDaoV1Notary},
		"tagus",
		&compliance.IssuerSetting{
			Key:                key,
			Alg:                jwa.PS256(),
			Issuer:             "did:web:did.dumss.me",
			VerificationMethod: "did:web:did.dumss.me#v2-2025",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// the only thing that is needed to accept the terms and conditions is an unique id for the vc you will receive.
	// if you want to know what you accept:
	// The PARTICIPANT signing the Self-Description agrees as follows:
	//	- to update its descriptions about any changes, be it technical, organizational, or legal
	//	- especially but not limited to contractual in regards to the indicated attributes present in the descriptions.
	//
	//
	//	The keypair used to sign Verifiable Credentials will be revoked where Gaia-X Association becomes aware of any inaccurate statements in regards to the claims which result in a non-compliance with the Trust Framework and policy rules defined in the Policy Rules and Labelling Document (PRLD).",
	//
	conditions, err := connector.SignTermsAndConditions("http://signedTC.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(conditions)
	err = conditions.Verify()
	if err != nil {
		t.Fatal(err)
	}

	//the current version of the Terms and Conditions can be retrieved from the clearing houses
	tc, err := connector.GetTermsAndConditions(compliance.TSystemsRegistryV1)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(tc)

}
