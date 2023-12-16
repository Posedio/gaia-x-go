/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package static

import (
	"embed"
	"errors"
	"io"
	"slices"
)

//go:embed jws2020_v1.json
var jws2020_v1 embed.FS

//go:embed credentials_v1.json
var credentials_v1 embed.FS

//go:embed trustframework.json
var trustframework embed.FS

// LoadKnownContextFromDisk is a fallback to load embedded json-ld files
func LoadKnownContextFromDisk(u string) (io.ReadCloser, error) {
	var file embed.FS
	var filename string
	if slices.Contains(knownContext, u) {
		switch u {
		case "https://w3id.org/security/suites/jws-2020/v1":
			file = jws2020_v1
			filename = "jws2020_v1.json"
		case "https://www.w3.org/2018/credentials/v1":
			file = credentials_v1
			filename = "credentials_v1.json"
		case "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#":
			file = trustframework
			filename = "trustframework.json"
		case "https://registry.lab.gaia-x.eu//main/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#":
			file = trustframework
			filename = "trustframework.json"
		default:
			return nil, errors.New("not embedded")
		}
	}

	dat, err := file.Open(filename)
	if err != nil {
		return nil, err
	}
	return dat, err
}

var knownContext = []string{
	"https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#",
	"https://registry.lab.gaia-x.eu//main/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#",
	"https://www.w3.org/2018/credentials/v1",
	"https://w3id.org/security/suites/jws-2020/v1",
}

func KnownContext() []string {
	return knownContext
}
