/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package examples

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/compliance"
	"os"
	"testing"
)

func TestSignTermsAndConditions(t *testing.T) {
	// at this point there is no way anymore to avoid a certificate with a qualified trust anchor.
	// for details how to load a certificate see the getKey function below
	key := getKey(t)

	// to accept the terms and conditions with YOUR digital identity first a compliance server has to be selected see compliance.ServiceUrl
	// version can stay on the 22.10 since is this is the most up-to-date version
	// there is no need for the legal registration number endpoint
	// as described above a private key with a public key that is signed by a qualified trust anchor is needed
	// as issuer a did as shown in 1_did is shown has to be provided
	// since a did can have multiple verification methods one that is used have to be specified, obviously this has to be the qualified public key to the set private key.
	connector, err := compliance.NewComplianceConnector(compliance.V1Staging, "", "22.10", key, "did:web:vc.mivp.group", "did:web:vc.mivp.group#X509-JWK2020")
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

	//the current version of the Terms and Conditions can be retrieved from the clearing houses
	tc, err := connector.GetTermsAndConditions(compliance.TSystemsRegistryV1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(tc)

}

// helper function to get the private key from certificate file
func getKey(t *testing.T) jwk.Key {
	path := os.Getenv("TestSignPrivateKeyFile")
	if path == "" {
		t.Fatal("missing env variable")
	}
	set, err := jwk.ReadFile(path, jwk.WithPEM(true))
	if err != nil {
		t.Fatal(err)
	}

	key, ok := set.Key(0)
	if !ok {
		t.Fatal("no key in set")
	}
	return key
}
