/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package examples

import (
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/compliance"
	"testing"
)

func TestCompliantServiceOfferingWithResourceAndExtension(t *testing.T) {
	// to retrieve a compliant participant credential, as described before a digital identity in this case a DID is needed
	// so first loading the private key is needed
	privateKey := getKey(t)

	// to establish a client we follow the steps we had already done
	connector, err := compliance.NewComplianceConnector(compliance.V1Staging, compliance.ArubaV1Notary, "22.10", privateKey, "did:web:vc.mivp.group", "did:web:vc.mivp.group#X509-JWK2020")
	if err != nil {
		t.Fatal(err)
	}

	lrnOptions := compliance.LegalRegistrationNumberOptions{
		Id:                 "http://lrn.test", // Id for the VerifiableCredential that it can be unique identified
		RegistrationNumber: "FR79537407926",   // Legal Registration Number in this case the on of the GAIA-X AISBL
		Type:               compliance.VatID,  // Type of the Legal Registration NUmber see List above
	}

	// retrieve the Legal Registration Number VC with the provided options
	legalRegistrationNumberVC, err := connector.SignLegalRegistrationNumber(lrnOptions)
	if err != nil {
		t.Fatal(err)
	}

	conditions, err := connector.SelfSignSignTermsAndConditions("http://signedTC.test")
	if err != nil {
		t.Fatal(err)
	}

	oc := []map[string]interface{}{{
		"@type": "gx:ServiceOffering",
		"gx:providedBy": map[string]interface{}{
			"id": "https://acme.org"},
		"gx:policy": "",
		"gx:termsAndConditions": map[string]interface{}{
			"gx:URL":  "http://termsandconds.com",
			"gx:hash": "d8402a23de560f5ab34b22d1a142feb9e13b3143",
		},
		"gx:dataAccountExport": map[string]interface{}{
			"gx:requestType": "API",
			"gx:accessType":  "digital",
			"gx:formatType":  "application/json",
		},
		"gx:aggregationOf": []map[string]interface{}{
			{
				"@id": "https://resource.test",
			},
		},
		"schema:Person": map[string]interface{}{
			"foaf:name": "John Doe",
		},
		"id": "https://some-acme-offering.org",
	}, {
		"@type":       "gx:ServiceAccessPoint",
		"@id":         "https://www.someWebsite.eu",
		"gx:name":     "website",
		"gx:host":     "someWebsite.eu",
		"gx:protocol": "https",
		"gx:version":  "1",
		"gx:port":     "443",
	}, {
		"@type":          "gx:PhysicalResource",
		"@id":            "eupg:some-server.acme.org",
		"gx:description": "some server from acme",
		"gx:ownedBy": map[string]interface{}{
			"@id": "https://acme.org",
		},
		"gx:maintainedBy": map[string]interface{}{
			"@id": "https://acme.org",
		},
	}, {
		"@type":          "gx:VirtualResource",
		"@id":            "eupg:some-virtual-server.acme.org",
		"gx:description": "some virtual server from acme",
		"gx:name":        "some vm of acme org",
		"gx:aggregationOf": []map[string]interface{}{{
			"@id": "eupg:some-server.acme.org",
		}},
		"gx:copyrightOwnedBy": map[string]interface{}{
			"@id": "https://acme.org",
		},
		"gx:license": "MIT",
		"gx:policy":  "%7B%22%40context%22%3A%22http%3A%2F%2Fwww.w3.org%2Fns%2Fodrl.jsonld%22%2C%22%40type%22%3A%22Set%22%2C%22uid%22%3A%22http%3A%2F%2Fexample.com%2Fpolicy%3A1010%22%2C%22permission%22%3A%5B%7B%22target%22%3A%22http%3A%2F%2Fexample.com%2Fasset%3A9898.movie%22%2C%22action%22%3A%22use%22%7D%5D%7D\n",
	},
	}

	options := compliance.ServiceOfferingComplianceOptions{
		Id: "https://some-acme-offering.org",
		ServiceOfferingOptions: compliance.ServiceOfferingOptionsAsMap{
			CustomContext:                    []string{"https://schema.org/version/latest/schemaorg-current-https.jsonld"},
			ServiceOfferingCredentialSubject: oc,
		},
		ParticipantComplianceOptions: compliance.ParticipantComplianceOptions{
			Id: "https://acme.org",
			Participant: compliance.ParticipantOptionsAsMap{
				ParticipantCredentialSubject: []map[string]interface{}{{
					"type":         "gx:LegalParticipant",
					"gx:legalName": "Gaia-X European Association for Data and Cloud AISBL",
					"gx:legalRegistrationNumber": map[string]interface{}{
						"id": legalRegistrationNumberVC.ID,
					},
					"gx:headquarterAddress": map[string]interface{}{
						"gx:countrySubdivisionCode": "BE-BRU",
					},
					"gx:legalAddress": map[string]interface{}{
						"gx:countrySubdivisionCode": "BE-BRU",
					},
					"id": "https://acme.org",
				}},
			},
			LegalRegistrationNumberVC: legalRegistrationNumberVC,
			TermAndConditionsVC:       conditions,
		},
	}

	offering, vp, err := connector.SignServiceOffering(options)
	if err != nil {
		t.Log(vp)
		t.Fatal(err)
	}

	t.Log(vp)

	t.Log(offering)

	err = offering.Verify()
	if err != nil {
		t.Log(err)
	}

}
