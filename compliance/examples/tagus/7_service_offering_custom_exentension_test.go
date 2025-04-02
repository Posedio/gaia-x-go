/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package loire

import (
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/compliance"
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/verifiableCredentials"
	"testing"
)

func TestCompliantServiceOfferingWithResourceAndExtension(t *testing.T) {
	// to retrieve a compliant participant credential, as described before a digital identity in this case a DID is needed
	// so first loading the private key is needed
	privateKey := getKey(t)

	// to establish a client we follow the steps we had already done
	connector, err := compliance.NewComplianceConnector(compliance.V1Staging, compliance.ArubaV1Notary, "tagus", privateKey, "did:web:did.dumss.me", "did:web:did.dumss.me#v1-2025")
	if err != nil {
		t.Fatal(err)
	}

	lrnOptions := compliance.LegalRegistrationNumberOptions{
		Id:                 "http://lrn.test",      // Id for the VerifiableCredential that it can be unique identified
		RegistrationNumber: "98450045E09C7F5A0703", // Legal Registration Number in this case the on of the GAIA-X AISBL
		Type:               compliance.LeiCode,     // Type of the Legal Registration NUmber see List above
	}

	// retrieve the Legal Registration Number VC with the provided options
	legalRegistrationNumberVC, err := connector.SignLegalRegistrationNumber(lrnOptions)
	if err != nil {
		t.Fatal(err)
	}

	// same as before a valid the terms and conditions have to be accepted
	conditions, err := connector.SelfSignSignTermsAndConditions("http://signedTC.test")
	if err != nil {
		t.Fatal(err)
	}

	oc := []map[string]interface{}{{
		"type": "gx:ServiceOffering",             // required to be identified as a service offering shape
		"id":   "https://some-acme-offering.org", // required, id of the service offering credential subject
		"gx:providedBy": map[string]interface{}{ // required
			"id": "https://acme.org"}, // the id of the gaia-x participant that provides the offering
		"gx:policy": "", // a policy has to set, or at least to be set on purpose set to nothing
		"gx:termsAndConditions": map[string]interface{}{ // required, a resolvable link to the service offering self-description related to the service and that can exist independently of it.
			"gx:URL":  "http://termsandconds.com",                 // required, a resolvable link to document
			"gx:hash": "d8402a23de560f5ab34b22d1a142feb9e13b3143", //required, sha256 hash of the above document.
		},
		"gx:dataAccountExport": map[string]interface{}{ // required, list of methods to export data from your user’s account out of the service
			"gx:requestType": "API",              // required, one of: "API","email","webform","unregisteredLetter","registeredLetter","supportCenter"
			"gx:accessType":  "digital",          // required, digital or physical
			"gx:formatType":  "application/json", // required, type of Media Types (formerly known as MIME types) as defined by the IANA
		},
		"gx:aggregationOf": []map[string]interface{}{ // optional, a list of other services and resources that are included in that service
			{
				"@id": "https://www.someWebsite.eu", // id from resource below
			}, {
				"@id": "eupg:some-config.acme.org", // id from resource below
			},
		},
		"schema:Person": map[string]interface{}{
			"foaf:name": "John Doe",
		},
	}, {
		"@type":       "gx:ServiceAccessPoint",      //optional resource, a list of Service Access Point which can be an endpoint as a mean to access and interact with the resource.
		"@id":         "https://www.someWebsite.eu", // id of the credential
		"gx:name":     "website",                    //optional
		"gx:host":     "someWebsite.eu",             //optional
		"gx:protocol": "https",                      //optional
		"gx:version":  "1",                          //optional
		"gx:port":     "443",                        //optional
	}, {
		"@type":          "gx:PhysicalResource",       //optional resource, a Physical resource is, but not limited to, a datacenter, a bare-metal service, a warehouse, a plant. Those are entities that have a weight and position in physical space.
		"@id":            "eupg:some-server.acme.org", // id of the credential
		"gx:description": "some server from acme",     // optional
		"gx:ownedBy": map[string]interface{}{ //optional, a list of resolvable links to Gaia-X Credentials of participant owning the resource.
			"@id": "https://acme.org",
		},
		"gx:maintainedBy": map[string]interface{}{ //required, a list of resolvable links to Gaia-X Credentials of participants maintaining the resource in operational condition and thus having physical access to it.
			"@id": "https://acme.org",
		},
	}, {
		"@type":          "gx:VirtualResource",        //optional, it represents static data in any form and necessary information such as dataset, configuration file, license, keypair, an AI model, neural network weights, etc.
		"@id":            "eupg:some-config.acme.org", // id of the credential
		"gx:description": "some config from acme",     //optional
		"gx:name":        "some config of acme org",   //optional
		"gx:aggregationOf": []map[string]interface{}{{ //optional, aggregation of other services or resources
			"@id": "eupg:some-server.acme.org", // in this case the virtual resource needs the physical resource
		}},
		"gx:copyrightOwnedBy": map[string]interface{}{ //required, A list of copyright owners either as a free form string or as resolvable link to Gaia-X Credential of participants. A copyright owner is a person or organization that has the right to exploit the resource. Copyright owner does not necessarily refer to the author of the resource, who is a natural person and may differ from copyright owner.
			"@id": "https://acme.org", //required, participant id
		},
		"gx:license": "MIT", //required, a list of SPDX identifiers or URL to document.
		"gx:policy":  "",    //required, a  list of policy expressed using a DSL (e.g., Rego or ODRL) (access control, throttling, usage, retention, ...). If there is no specified usage policy constraints on the VirtualResource, the  policy should express a simple default: allow intent"
	},
	}

	// same is in unit 5 service offerings
	options := compliance.ServiceOfferingComplianceOptions{
		Id: "https://some-acme-offering.org",
		ServiceOfferingOptions: compliance.ServiceOfferingOptionsAsMap{
			ServiceOfferingCredentialSubject: oc,
			CustomContext:                    []verifiableCredentials.Namespace{{"", "https://schema.org/version/latest/schemaorg-current-https.jsonld"}},
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

	t.Log(offering)

	err = offering.Verify()
	if err != nil {
		t.Log(err)
	}

	cus := []map[string]interface{}{{
		"type":      "schema:person",
		"id":        "https://some-acme-offering.org",
		"foaf:name": "John Doe",
	}, {
		"type": "gx:ServiceOffering",
		"id":   "https://some-acme-offering.org",
	}}

	sign, err := connector.SelfSignCredentialSubject("https://some-acme-offering.org", cus)
	if err != nil {
		t.Fatal(err)
	}

	sign.Context.Context = append(sign.Context.Context, verifiableCredentials.Namespace{"", "https://schema.org/version/latest/schemaorg-current-https.jsonld"})

	err = connector.ReSelfSign(sign)
	if err != nil {
		t.Fatal(err)
	}

	vp.VerifiableCredential = append(vp.VerifiableCredential, sign)

	t.Log(vp)

}
