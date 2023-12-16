/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package verifiableCredentials

import (
	"fmt"
	"github.com/piprate/json-gold/ld"
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/verifiableCredentials/static"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sync"
	"time"
)

type cache struct {
	document *ld.RemoteDocument
}

// DocumentLoader fork from ld.DefaultDocumentLoader https://github.com/piprate/json-gold/blob/master/ld/document_loader.go
type DocumentLoader struct {
	httpClient *http.Client
	cache      map[string]*cache
	mux        sync.RWMutex
}

// NewDocumentLoader fork from ld.DefaultDocumentLoader https://github.com/piprate/json-gold/blob/master/ld/document_loader.go
func NewDocumentLoader(httpClient *http.Client) *DocumentLoader {
	rval := &DocumentLoader{httpClient: httpClient}

	if rval.httpClient == nil {
		rval.httpClient = http.DefaultClient
	}

	rval.cache = make(map[string]*cache)

	return rval
}

// LoadDocument returns a RemoteDocument containing the contents of the JSON resource
// from the given URL. fork from https://github.com/piprate/json-gold/blob/master/ld/document_loader.go
func (dl *DocumentLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	dl.mux.RLock()
	if doc, k := dl.cache[u]; k {
		dl.mux.RUnlock()
		return doc.document, nil
	}
	dl.mux.RUnlock()

	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, fmt.Sprintf("error parsing URL: %s", u))
	}

	remoteDoc := &ld.RemoteDocument{}

	protocol := parsedURL.Scheme
	if protocol != "http" && protocol != "https" {
		// Can't use the HTTP client for those!
		remoteDoc.DocumentURL = u
		var file *os.File
		file, err = os.Open(u)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
		defer func(file *os.File) {
			_ = file.Close()
		}(file)

		remoteDoc.Document, err = ld.DocumentFromReader(file)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
	} else {
		req, err := http.NewRequest("GET", u, http.NoBody)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
		// We prefer application/ld+json, but fallback to application/json
		// or whatever is available
		acceptHeader := "application/ld+json, application/json;q=0.9, application/javascript;q=0.5, text/javascript;q=0.5, text/plain;q=0.2, */*;q=0.1"

		req.Header.Add("Accept", acceptHeader)

		res, err := dl.httpClient.Do(req)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(res.Body)

		fallback := false

		if res.StatusCode == http.StatusTooManyRequests {
			disk, err := static.LoadKnownContextFromDisk(u)
			if err == nil {
				res.Body = disk
				fallback = true
			}
		}

		if res.StatusCode != http.StatusOK && !fallback {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed,
				fmt.Sprintf("Bad response status code: %d", res.StatusCode))
		}

		remoteDoc.DocumentURL = res.Request.URL.String()

		contentType := res.Header.Get("Content-Type")
		linkHeader := res.Header.Get("Link")

		if len(linkHeader) > 0 {
			parsedLinkHeader := ld.ParseLinkHeader(linkHeader)
			linkHeaderRel := "http://www.w3.org/ns/json-ld#context"
			contextLink := parsedLinkHeader[linkHeaderRel]
			rApplicationJSON := regexp.MustCompile(`^application/(\w*\+)?json$`)
			if contextLink != nil && contentType != ld.ApplicationJSONLDType &&
				(contentType == "application/json" || rApplicationJSON.MatchString(contentType)) {

				if len(contextLink) > 1 {
					return nil, ld.NewJsonLdError(ld.MultipleContextLinkHeaders, nil)
				} else if len(contextLink) == 1 {
					remoteDoc.ContextURL = contextLink[0]["target"]
				}
			}

			// If content-type is not application/ld+json, nor any other +json
			// and a link with rel=alternate and type='application/ld+json' is found,
			// use that instead
			alternateLink := parsedLinkHeader["alternate"]
			if len(alternateLink) > 0 &&
				alternateLink[0]["type"] == ld.ApplicationJSONLDType &&
				!rApplicationJSON.MatchString(contentType) {

				finalURL := ld.Resolve(u, alternateLink[0]["target"])
				return dl.LoadDocument(finalURL)
			}
		}

		remoteDoc.Document, err = ld.DocumentFromReader(res.Body)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
	}

	dl.mux.Lock()
	dl.cache[u] = &cache{
		document: remoteDoc,
	}

	timeout := 1 * time.Minute

	if slices.Contains(static.KnownContext(), u) {
		timeout = 24 * time.Hour
	}

	time.AfterFunc(timeout, func() {
		dl.mux.Lock()
		delete(dl.cache, u)
		dl.mux.Unlock()
	})
	dl.mux.Unlock()

	return remoteDoc, nil
}
