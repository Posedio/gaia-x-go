/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package compliance

import (
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"os"
	"testing"
)

func TestVatSigned(t *testing.T) {
	path := os.Getenv("TestSignPrivateKeyFile")
	if path == "" {
		t.Fatal("missing env variable")
	}
	set, err := jwk.ReadFile(path, jwk.WithPEM(true))
	if err != nil {
		t.Fatal(err)
	}

	raw, ok := set.Key(0)
	if !ok {
		t.Fatal("no key in set")
	}

	c, err := NewComplianceConnector(signUrlB, ArubaV1Notary, "22.10", raw, "did:web:vc.mivp.group", "did:web:vc.mivp.group#X509-JWK2020")
	if err != nil {
		t.Fatal(err)
	}

	lrnOptions := LegalRegistrationNumberOptions{
		Id:                 "https://test.test.test",
		RegistrationNumber: "FR79537407926",
		Type:               VatID,
	}

	number, err := c.SignLegalRegistrationNumber(lrnOptions)
	if err != nil {
		t.Fatal(err)
	}

	testJ, err := json.MarshalIndent(number, "", "	")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(testJ))

	err = number.Verify()
	if err != nil {
		t.Fatal(err)
	}

}
