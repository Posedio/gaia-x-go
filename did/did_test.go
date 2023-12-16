/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package did

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDid(t *testing.T) {
	jsonData := []byte(`
{
	"id": "did:web:did.dumss.me",
	"alsoKnownAs": ["stefan"],
	"controller": "test",
	"keyAgreement": [{
		"id": "did:web:did.dumss.me:user:stefan",
		"controller": "did.dumss.me",
		"type": "did"
	}],
	"@context":["https://www.w3.org/ns/did/v1"]
}`)
	var test DID
	err := json.Unmarshal(jsonData, &test)
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(test)
	assert.JSONEq(t, string(j), string(jsonData))
	jsonData2 := []byte(`
{
	"id": "did:web:did.dumss.me",
	"alsoKnownAs": ["stefan"],
	"controller": "[test]",
	"authentication": ["did:web:did.dumss.me"],
	"keyAgreement": [{
		"id": "did:web:did.dumss.me:user:stefan",
		"controller": "did.dumss.me",
		"type": "did"
	}],
	"@context":["https://www.w3.org/ns/did/v1"]
}`)
	var test2 DID
	err = json.Unmarshal(jsonData2, &test2)
	if err != nil {
		t.Fatal(err)
	}
	j2, _ := json.MarshalIndent(test2, "", "\t")
	assert.JSONEq(t, string(j2), string(jsonData2))
	jsonData3 := []byte(`
{
	"id": "did:web:did.dumss.me",
	"@context":["https://www.w3.org/ns/did/v1"],
	"alsoKnownAs": ["stefan"],
	"controller": "[test]",
	"authentication": ["did:web:did.dumss.me", "did:web:did.dumss.me"],
	"keyAgreement": [{
		"id": "did:web:did.dumss.me:user:stefan",
		"controller": "did1.dumss.me",
		"type": "did"
	},
	{
		"id": "did:web:did.dumss.me:user:stefan2",
		"controller": "did2.dumss.me",
		"type": "did2"
	},
	"did:web:did.dumss.me"]
}`)
	var test3 DID
	err = json.Unmarshal(jsonData3, &test3)
	if err != nil {
		t.Fatal(err)
	}
	j3, _ := json.MarshalIndent(test3, "", "\t")
	assert.JSONEq(t, string(j3), string(jsonData3))
}

func TestDIDdWeb(t *testing.T) {
	//check basic did:web
	j, err := ResolveDIDWeb("did:web:vc.mivp.group")
	if err != nil {
		t.Fatal(err)
	}
	err = j.ResolveMethods()
	if err != nil {
		t.Fatal(err)
	}

	//check on error of wrong path
	_, err = ResolveDIDWeb("did:web:vc.mivp.group:wrong:user:stefan")
	if err != nil {
		if strings.Contains(err.Error(), "403") {
			assert.EqualErrorf(t, err, "Server responded with 403 not with 200 (OK) status code", "error should be statuscode 404")
		} else {
			assert.EqualErrorf(t, err, "Server responded with 404 not with 200 (OK) status code", "error should be statuscode 404")
		}
	} else {
		t.Fatal("Server responded on not with expected error 404")
	}
}

func TestUniResolve(t *testing.T) {
	did, err := UniResolverDID("did:web:vc.mivp.group")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(did)
}
