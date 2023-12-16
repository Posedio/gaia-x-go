/*
MIT License
Copyright (c) 2023 Stefan Dumss, MIVP TU Wien
*/

package compliance

import (
	"crypto/sha256"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// hash256 returns the sha256 hex representation of the given byte slice
func hash256(sd []byte) string {
	h := sha256.New()
	h.Write(sd)

	ha := h.Sum(nil)

	hash := fmt.Sprintf("%x", ha)
	return hash
}

// generateJWS sd has to be the normalized sd
func generateJWS(sd []byte, privateKey jwk.Key) ([]byte, string, error) {
	hash := hash256(sd)

	header := jws.NewHeaders()
	err := header.Set("b64", false)
	if err != nil {
		return nil, "", err
	}
	err = header.Set("crit", []string{"b64"})
	if err != nil {
		return nil, "", err
	}

	buf, err := jws.Sign(nil, jws.WithKey(jwa.PS256, privateKey, jws.WithProtectedHeaders(header)), jws.WithDetachedPayload([]byte(hash)))
	if err != nil {
		return nil, "", err
	}

	return buf, hash, nil
}
