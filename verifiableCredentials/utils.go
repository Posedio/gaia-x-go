/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package verifiableCredentials

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jws"
	"gitlab.euprogigant.kube.a1.digital/stefan.dumss/gaia-x-go/did"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func VerifyCertChain(url string) (*x509.Certificate, error) {
	c := http.Client{Timeout: time.Second * 2}
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	do, err := c.Do(request)
	if err != nil {
		return nil, err
	}
	if do.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cert not loadable: %v", do.Status)
	}
	certBytes, err := io.ReadAll(do.Body)
	if err != nil {
		return nil, err
	}
	block, next := pem.Decode(certBytes)
	if block == nil {
		return nil, errors.New("empty certificate block or malformed certificate ")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	for {
		block, next = pem.Decode(next)
		if block == nil {
			break
		}

		inter, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		roots.AddCert(inter)
		if len(next) == 0 {
			break
		}
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		log.Println("certificate does not allow digital signature")
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		_, err = cert.Verify(x509.VerifyOptions{})
		if err != nil {
			return nil, err
		}

	}

	return cert, nil
}

func VCFromJWT(token []byte) (*VerifiableCredential, error) {
	dids, err := VerifyJWS(token)
	if err != nil {
		return nil, err
	}
	var signaturesErr error

	for didweb, header := range dids {
		key, k := didweb.Keys[header.KID]
		if !k {
			signaturesErr = errors.Join(signaturesErr, fmt.Errorf("key %v not in did web %v", header.KID, header.Issuer))
			continue
		}

		payload, err := jws.Verify(token, jws.WithKey(header.Algorithm, key.JWK))
		if err != nil {
			signaturesErr = errors.Join(signaturesErr, err)
			continue
		}

		vc := &VerifiableCredential{}

		err = json.Unmarshal(payload, vc)
		if err != nil {
			signaturesErr = errors.Join(signaturesErr, err)
			continue
		}
		vc.signature = &JWSSignature{
			OriginalJWT: token,
			DID:         didweb,
			JWTHeader:   header,
		}
		return vc, nil
	}
	return nil, signaturesErr
}

func VPFROMJWT(token []byte) (*VerifiablePresentation, error) {
	dids, err := VerifyJWS(token)
	if err != nil {
		return nil, err
	}
	var signaturesErr error

	for didweb, header := range dids {
		key, k := didweb.Keys[header.KID]
		if !k {
			signaturesErr = errors.Join(signaturesErr, fmt.Errorf("key %v not in did web %v", header.KID, header.Issuer))
			continue
		}

		payload, err := jws.Verify(token, jws.WithKey(header.Algorithm, key.JWK))
		if err != nil {
			signaturesErr = errors.Join(signaturesErr, err)
			continue
		}

		vp := &VerifiablePresentation{}

		err = json.Unmarshal(payload, vp)
		if err != nil {
			signaturesErr = errors.Join(signaturesErr, err)
			continue
		}
		vp.signature = &JWSSignature{
			OriginalJWT: token,
			DID:         didweb,
			JWTHeader:   header,
		}
		return vp, nil
	}
	return nil, signaturesErr
}

func VerifyJWS(token []byte) (map[*did.DID]*JWTHeader, error) {
	parse, err := jws.Parse(token)
	if err != nil {
		return nil, err
	}
	signatures := parse.Signatures()

	var resolveSigErr error

	dids := map[*did.DID]*JWTHeader{}

	for _, signature := range signatures {
		marshalJSON, err := signature.ProtectedHeaders().MarshalJSON()
		if err != nil {
			resolveSigErr = errors.Join(resolveSigErr, err)
			continue
		}

		header := &JWTHeader{}

		err = json.Unmarshal(marshalJSON, header)
		if err != nil {
			resolveSigErr = errors.Join(resolveSigErr, err)
			continue
		}

		didweb, err := did.ResolveDIDWeb(header.Issuer)
		if err != nil {
			resolveSigErr = errors.Join(resolveSigErr, err)
			continue
		}

		err = didweb.ResolveMethods()
		if err != nil {
			resolveSigErr = errors.Join(resolveSigErr, err)
			continue
		}
		dids[didweb] = header
	}

	if len(dids) == 0 {
		return nil, resolveSigErr
	}
	return dids, nil
}

func JWTFromID(id string) ([]byte, error) {
	split := strings.Split(id, ",")
	if len(split) != 2 {
		return nil, errors.New("invalid JWT ID format")
	}
	return []byte(split[1]), nil
}

type URL struct {
	Value string `json:"@value"`
	Type  string `json:"@type"`
}

var XSDanyURI = "xsd:anyURI"

func WithAnyURI(value string) URL {
	return URL{
		Value: value,
		Type:  XSDanyURI,
	}
}

func toMap(obj interface{}) (map[string]interface{}, error) {
	j, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var m = map[string]interface{}{}
	err = json.Unmarshal(j, &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}
