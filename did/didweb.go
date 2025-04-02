/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//DID Web defined by https://w3c-ccg.github.io/did-method-web/

var httpclient = &http.Client{
	Timeout: 5 * time.Second,
	/* REMOVED since some people have redirects on their DID
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	*/
}

func request(path *url.URL) (*DID, error) {
	did := &DID{}

	req, err := http.NewRequest("GET", path.String(), nil)
	if err != nil {
		return nil, err
	}

	response, err := httpclient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	if response.StatusCode == 400 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("response from uni resolver: %v", string(body))
	}

	if response.StatusCode != 200 {
		e := fmt.Sprintf("Server responded with %v not with 200 (OK) status code", response.StatusCode)
		return nil, errors.New(e)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, did)
	if err != nil {
		uniDID := &UniResolved{}
		err := json.Unmarshal(body, uniDID)
		if err != nil {
			return nil, err
		}
		did = uniDID.DidDocument
	}

	//check if the context is a did
	if did.Context[0] != "https://w3id.org/did/v1" {
		if did.Context[0] != "https://www.w3.org/ns/did/v1" {
			return nil, errors.New("@context not supported or missing")
		}
	}

	return did, nil
}

/*
ResolveDIDWeb resolves the given DID:WEB to a struct DID
*/
func ResolveDIDWeb(didweb string) (*DID, error) {

	var fragment string

	if strings.Contains(didweb, "#") {
		temp := strings.Split(didweb, "#")
		didweb = temp[0]
		fragment = temp[1]
	}

	sweb := strings.Split(didweb, "web:")

	if len(sweb) < 2 {
		return nil, errors.New("malformed did:web")
	}

	p := strings.ReplaceAll(sweb[1], ":", "/")

	p = strings.ReplaceAll(p, "%3A", ":")

	squery := strings.Split(sweb[len(sweb)-1], "?")

	var qf string

	if len(squery) > 1 {
		p = strings.ReplaceAll(p, "?"+squery[1], "")
		qf = squery[1]
	} else {
		qf = ""
	}

	var path string

	if !strings.Contains(p, "/") {
		path = "https://" + p + "/.well-known/did.json"
	} else {
		path = "https://" + p + "/did.json"
	}
	if qf != "" {
		path = path + "?" + qf
	}

	if fragment != "" {
		path = path + "#" + fragment
	}

	u, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	d, err := request(u)
	if err != nil {
		return nil, err
	}

	return d, nil

}

/*
UniResolverDID uses the with on UniResolverURL hosted universal resolver to resolve the did
*/
func UniResolverDID(did string) (*DID, error) {
	path := UniResolverURL + did
	u, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	d, err := request(u)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// UniResolved is a struct to marshal the retrieved json
type UniResolved struct {
	Context               string `json:"@context"`
	DidDocument           *DID   `json:"didDocument"`
	DidResolutionMetadata struct {
		ContentType string `json:"contentType"`
		Pattern     string `json:"pattern"`
		DriverURL   string `json:"driverUrl"`
		Duration    int    `json:"duration"`
		Did         struct {
			DidString        string `json:"didString"`
			MethodSpecificID string `json:"methodSpecificId"`
			Method           string `json:"method"`
		} `json:"did"`
	} `json:"didResolutionMetadata"`
	DidDocumentMetadata map[string]interface{} `json:"didDocumentMetadata"`
}
