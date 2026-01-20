package loire

import (
	"testing"
	"time"

	"github.com/Posedio/gaia-x-go/gxTypes"
	"github.com/Posedio/gaia-x-go/signer"
	vc "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

func TestSignerOnly(t *testing.T) {
	var idprefix = "https://did.dumss.me/"
	var issuer = "did:web:did.dumss.me"

	// set up a signer
	sign, err := signer.NewSigner(
		&signer.IssuerSetting{
			Key:                key, //jwk.Key
			Alg:                jwa.PS256(),
			Issuer:             issuer,
			VerificationMethod: "did:web:did.dumss.me#v3-2025",
		})
	if err != nil {
		t.Fatal(err)
	}

	//prepare Verifiable Presentation
	vp := vc.NewEmptyVerifiablePresentationV2()

	addressVC, err := vc.NewEmptyVerifiableCredentialV2(
		vc.WithVCID(idprefix+"address"),
		vc.WithValidFromNow(),
		vc.WithGaiaXContext(),
		vc.WithIssuer(issuer),
		vc.WithAdditionalTypes("gx:Address"),
		vc.WithValidFor(time.Hour*24*365))
	if err != nil {
		t.Fatal(err)
	}

	// defined structs, it used json serialization internal
	addressCS := gxTypes.Address{
		CredentialSubjectShape: vc.CredentialSubjectShape{ID: addressVC.ID + "#cs"},
		CountryCode:            "AT",
		CountryName:            "Austria",
		PostalCode:             "1040",
		StreetAddress:          "Weyringergasse 1-3/DG ",
		Locality:               "Vienna",
	}

	err = addressVC.AddToCredentialSubject(addressCS)
	if err != nil {
		t.Fatal(err)
	}

	// map example
	mapExample := map[string]interface{}{
		"example": "test",
	}

	err = addressVC.AddToCredentialSubject(mapExample)
	if err != nil {
		t.Fatal(err)
	}

	err = sign.SelfSign(addressVC)
	if err != nil {
		t.Fatal(err)
	}

	err = addressVC.Verify()
	if err != nil {
		t.Fatal(err)
	}

	vp.AddEnvelopedVC(addressVC.GetOriginalJWS())

	err = sign.SelfSignPresentation(vp, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(vp.GetOriginalJWS()))

}
