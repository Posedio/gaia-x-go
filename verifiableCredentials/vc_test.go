package verifiableCredentials

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestVC(t *testing.T) {
	//var s = []byte("eyJhbGciOiJQUzI1NiIsImlzcyI6ImRpZDp3ZWI6Z3gtbm90YXJ5Lmd4ZGNoLmRpaC50ZWxla29tLmNvbTp2MiIsImtpZCI6ImRpZDp3ZWI6Z3gtbm90YXJ5Lmd4ZGNoLmRpaC50ZWxla29tLmNvbTp2MiNYNTA5LUpXSyIsImlhdCI6MTc0MTI3MTYxMTIwNiwiZXhwIjoxNzQ5MDQ3NjExMjA3LCJjdHkiOiJ2YytsZCIsInR5cCI6InZjK2xkK2p3dCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3czaWQub3JnL2dhaWEteC9kZXZlbG9wbWVudCMiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsImd4OkxlaUNvZGUiXSwiaWQiOiJodHRwczovL2V4YW1wbGUub3JnL2NyZWRlbnRpYWxzLzEyMyIsIm5hbWUiOiJMRUkgQ29kZSIsImRlc2NyaXB0aW9uIjoiTGVnYWwgRW50aXR5IElkZW50aWZpZXIiLCJpc3N1ZXIiOiJkaWQ6d2ViOmd4LW5vdGFyeS5neGRjaC5kaWgudGVsZWtvbS5jb206djIiLCJ2YWxpZEZyb20iOiIyMDI1LTAzLTA2VDE0OjMzOjMxLjIwNiswMDowMCIsInZhbGlkVW50aWwiOiIyMDI1LTA2LTA0VDE0OjMzOjMxLjIwNyswMDowMCIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7IkBjb250ZXh0Ijp7InNjaGVtYSI6Imh0dHBzOi8vc2NoZW1hLm9yZy8ifSwiaWQiOiJodHRwczovL2V4YW1wbGUub3JnL3N1YmplY3RzLzEyMyIsInR5cGUiOiJneDpMZWlDb2RlIiwic2NoZW1hOmxlaUNvZGUiOiI5Njk1MDA3NTg2R0NBS1BZSjcwMyIsImd4OmNvdW50cnlDb2RlIjoiRlIiLCJneDpzdWJkaXZpc2lvbkNvdW50cnlDb2RlIjpudWxsfSwiZXZpZGVuY2UiOnsiZ3g6ZXZpZGVuY2VPZiI6Imd4OkxlaUNvZGUiLCJneDpldmlkZW5jZVVSTCI6Imh0dHBzOi8vYXBpLmdsZWlmLm9yZy9hcGkvdjEvbGVpLXJlY29yZHMvOTY5NTAwNzU4NkdDQUtQWUo3MDMiLCJneDpleGVjdXRpb25EYXRlIjoiMjAyNS0wMy0wNlQxNDozMzozMS4yMDYrMDA6MDAifX0.Dj1xdxpI9y3h6sREsrPdb1MbbEYdYWoY58Grw-blgSgl2DGNjU4QVGM3XBNFyuTNwnHANYd63uxQXypUcZDWkUDZ6OjijGyVGK6IXquToY2P3OqulhOkRX8Hv989UvFm5yeSoIjLgFn2WyVYD8Ciu6k-4vlrm_teO3mG2EFaSNhkYzKUURFjENVYvd-eQgkkUJjOSJPK4zo0TAEawlUz4lMTZ9AFPLpvmjZUYa0rtf-1EHAIMOnC_kkbMefj2Y31_zZ1QJvMsb-x4BYScc2UZXw5TuJmvfi8ijo5jvX1UBFhsqsv90egm2E8HqL8dhe_Q-cO3teuH9gYpxmUZXIrQnqqAPuR0TpcjiFuLZ84o0cXqozrwdDR68PvAcN1R27o3fyZeuZI6FaQTb7A5ZdZEgdBBhFWM5OGgL89lykRtMNcYzWM5rxuUUAQ-MxezNBVRtPzzFMslKs0AA2ObvKYsp-TZUnoSR_VJ2iWG7S9cG5yay27KXfxLb3zq8LJofLEjhogZIjkbPz6uvI0oH-5Z_ym8yLFWXE_ya9CjXMqoDe51E3wWPu9QI22wjrhRsNhd67WznZHmeZsEUULlEsJQ2nR9m8-abSAPnidzZO8L7gvnZdfjyeWlyvGoNF4WQIrW-V_BkIDBTNi5wAl3spF3DitoVak5OaY-9ET6tfhFP0")
	//var s = []byte("eyJhbGciOiJQUzI1NiIsImlzcyI6ImRpZDp3ZWI6cmVnaXN0cmF0aW9ubnVtYmVyLm5vdGFyeS5sYWIuZ2FpYS14LmV1Om1haW4iLCJraWQiOiJkaWQ6d2ViOnJlZ2lzdHJhdGlvbm51bWJlci5ub3RhcnkubGFiLmdhaWEteC5ldTptYWluI1g1MDktSldLIiwiaWF0IjoxNzQxMjcyOTYxODcxLCJleHAiOjE3NDkwNDg5NjE4NzIsImN0eSI6InZjK2xkIiwidHlwIjoidmMrbGQrand0In0.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3czaWQub3JnL2dhaWEteC9kZXZlbG9wbWVudCMiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsImd4OkxlaUNvZGUiXSwiaWQiOiJodHRwczovL2V4YW1wbGUub3JnL2NyZWRlbnRpYWxzLzEyMyIsIm5hbWUiOiJMRUkgQ29kZSIsImRlc2NyaXB0aW9uIjoiTGVnYWwgRW50aXR5IElkZW50aWZpZXIiLCJpc3N1ZXIiOiJkaWQ6d2ViOnJlZ2lzdHJhdGlvbm51bWJlci5ub3RhcnkubGFiLmdhaWEteC5ldTptYWluIiwidmFsaWRGcm9tIjoiMjAyNS0wMy0wNlQxNDo1NjowMS44NzErMDA6MDAiLCJ2YWxpZFVudGlsIjoiMjAyNS0wNi0wNFQxNDo1NjowMS44NzIrMDA6MDAiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJAY29udGV4dCI6eyJzY2hlbWEiOiJodHRwczovL3NjaGVtYS5vcmcvIn0sImlkIjoiaHR0cHM6Ly9leGFtcGxlLm9yZy9zdWJqZWN0cy8xMjMiLCJ0eXBlIjoiZ3g6TGVpQ29kZSIsInNjaGVtYTpsZWlDb2RlIjoiOTY5NTAwNzU4NkdDQUtQWUo3MDMiLCJneDpjb3VudHJ5Q29kZSI6IkZSIiwiZ3g6c3ViZGl2aXNpb25Db3VudHJ5Q29kZSI6bnVsbH0sImV2aWRlbmNlIjp7Imd4OmV2aWRlbmNlT2YiOiJneDpMZWlDb2RlIiwiZ3g6ZXZpZGVuY2VVUkwiOiJodHRwczovL2FwaS5nbGVpZi5vcmcvYXBpL3YxL2xlaS1yZWNvcmRzLzk2OTUwMDc1ODZHQ0FLUFlKNzAzIiwiZ3g6ZXhlY3V0aW9uRGF0ZSI6IjIwMjUtMDMtMDZUMTQ6NTY6MDEuODcxKzAwOjAwIn19.qIzJLAgzeKAuUXzbER2hyXDkq4AB9C8f0inRpJnVs8wEGW-6n8NAfMKgaVF8B3Y8azPdaWK_HwsuauS2R87O7SK2f-54LW_brCIg8JfFHHAypRYMmw2iyc5Yen_5h9bZd7pmnb5siT3e5JgH541MBEsdi47RoAvcPEpZlA6JHKwtLXqXR-PgZQXuISHgkeTSVrpkuSdiahCcOvSRRK1K08wG7_R3PbLWXv7ZIO34gV4UyYzAshb0usHn-1-HsMSpvfseNoegkAr5_ITwud2z-NRuO-ii_Pvdfm1qz0ve3uVQCIZ7Vto3e0VWF_UWNszfR1lE6oaHSKvnRGyglvb-sg")
	var s = []byte("eyJhbGciOiJQUzI1NiIsImlzcyI6ImRpZDp3ZWI6d3d3LmRlbHRhLWRhby5jb206bm90YXJ5OnYyIiwia2lkIjoiZGlkOndlYjp3d3cuZGVsdGEtZGFvLmNvbTpub3Rhcnk6djIjWDUwOS1KV0siLCJpYXQiOjE3NDEyNzMwMzY3MjgsImV4cCI6MTc0NTEwNzE5OTAwMCwiY3R5IjoidmMrbGQiLCJ0eXAiOiJ2YytsZCtqd3QifQ.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3czaWQub3JnL2dhaWEteC9kZXZlbG9wbWVudCMiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpZCI6Imh0dHBzOi8vZXhhbXBsZS5vcmcvY3JlZGVudGlhbHMvMTIzIiwibmFtZSI6IkxFSSBDb2RlIiwiZGVzY3JpcHRpb24iOiJMZWdhbCBFbnRpdHkgSWRlbnRpZmllciIsImlzc3VlciI6ImRpZDp3ZWI6d3d3LmRlbHRhLWRhby5jb206bm90YXJ5OnYyIiwidmFsaWRGcm9tIjoiMjAyNS0wMy0wNlQxNDo1NzoxNi43MjgrMDA6MDAiLCJ2YWxpZFVudGlsIjoiMjAyNS0wNC0xOVQyMzo1OTo1OS4wMDArMDA6MDAiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJAY29udGV4dCI6eyJzY2hlbWEiOiJodHRwczovL3NjaGVtYS5vcmcvIn0sImlkIjoiaHR0cHM6Ly9leGFtcGxlLm9yZy9zdWJqZWN0cy8xMjMiLCJ0eXBlIjoiZ3g6TGVpQ29kZSIsInNjaGVtYTpsZWlDb2RlIjoiOTY5NTAwNzU4NkdDQUtQWUo3MDMiLCJneDpjb3VudHJ5Q29kZSI6IkZSIiwiZ3g6c3ViZGl2aXNpb25Db3VudHJ5Q29kZSI6bnVsbH0sImV2aWRlbmNlIjp7Imd4OmV2aWRlbmNlT2YiOiJMRUlfQ09ERSIsImd4OmV2aWRlbmNlVVJMIjoiaHR0cHM6Ly9hcGkuZ2xlaWYub3JnL2FwaS92MS9sZWktcmVjb3Jkcy85Njk1MDA3NTg2R0NBS1BZSjcwMyIsImd4OmV4ZWN1dGlvbkRhdGUiOiIyMDI1LTAzLTA2VDE0OjU3OjE2LjcyOCswMDowMCJ9fQ.alKgiN2Wvm3MGWOzZF-VZg3vH2K4sQKaETh6085d0vqAhBlwwj467mnO2kUJeuKu1FoNT7XnP3Kezf8nAH8WyIuw_t0Wnq9fVKX1d0myc_yH36uA243fhutwbIsayaZcnzAQ-GsEfsduE76XerjN8o6wRHHsv366EZCpmiqSXWpKL5z6yf1wi1oRpXfGyN-phTpJ6mGE395U7JDxbByxSjYuC8NcH__vKMTf66qAmorPKwrQ5PP4CRd59X2FuPQZRPYvcV0H5v-E3CHBKtmE8OoUiIFmI1kr33SSuqWYEZuiCU_Owst-2FEL1CJWR5ctOGdjz7a-viZgR_JUs732fRdbPHrA8w1n_CpwRXZ30Pw_0mu6uAG_EibyazwpoBn35bUINyOkbAbfNYo3y4rXssH5tF9pKfR4-jWRZqdNXTsH7WG_VzGnTd9O36TzfT1lCHar5jfqFtZhAl4svSe6uCVY2XSEXMP2cH73NqbhgJhY11jcNM6k0csGkRdzlqtuBRT6fe0W_RKiwzEXfmIzWCM_JFgBCaBMpEVoCp1LnnZHCdekXV3iL_bz0nYrwLEj9Cz6Jf6v1TqdlhBJi0nfZVaCSR5gBV9SILMktbrxLkbZKA0t61cPI_wnJ8yDkil6r3-isRBQFfSNkuaoxJTIuiwNcwZMiR7FQUK2fYKLO_c")

	vc, err := VCFromJWT(s)
	if err != nil {
		t.Fatal(err)
	}

	err = vc.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}

	err = vc.Validate(validator.New())
	if err != nil {
		t.Fatal(err)
	}

	canonizeGo, err := vc.CanonizeGo()
	if err != nil {
		t.Fatal(err)
	}

	jsc, err := vc.JSC()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(vc)

	headers := jws.NewHeaders()
	err = headers.Set("alg", jwa.PS256)
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("iss", "did:web:did.dumss.me")
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("kid", "did:web:did.dumss.me#v1-2025")
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("iat", time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("exp", time.Now().UnixMilli()+(time.Hour*24*30).Milliseconds())
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("cty", "vc+ld")
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("typ", "vc+ld+jwt")
	if err != nil {
		t.Fatal(err)
	}

	pkey := getKey(t)

	buf, err := jws.Sign(jsc, jws.WithKey(jwa.PS256, pkey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatal(err)
	}

	vc2, err := VCFromJWT(buf)
	if err != nil {
		t.Fatal(err)
	}

	bytes, err := vc2.CanonizeGo()
	if err != nil {
		assert.Equal(t, canonizeGo, bytes)
	}

	err = vc2.Verify(nil)
	if err != nil {
		assert.Equal(t, "credential issuer does not match JTW issuer", err.Error())
	}

}

func getKey(t *testing.T) jwk.Key {
	path := os.Getenv("TestSignPrivateKeyFile")
	if path == "" {
		t.Fatal("missing env variable")
	}
	set, err := jwk.ReadFile(path, jwk.WithPEM(true))
	if err != nil {
		t.Fatal(err)
	}

	key, ok := set.Key(0)
	if !ok {
		t.Fatal("no key in set")
	}
	return key
}

func JWSFromVC(t *testing.T, credential *VerifiableCredential) []byte {
	headers := jws.NewHeaders()
	err := headers.Set("alg", jwa.PS256)
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("iss", "did:web:did.dumss.me")
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("kid", "did:web:did.dumss.me#v1-2025")
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("iat", time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("exp", time.Now().UnixMilli()+(time.Hour*24*30).Milliseconds())
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("cty", "vc+ld")
	if err != nil {
		t.Fatal(err)
	}
	err = headers.Set("typ", "vc+ld+jwt")
	if err != nil {
		t.Fatal(err)
	}

	pkey := getKey(t)

	jsc, err := credential.JSC()
	if err != nil {
		t.Fatal(err)
	}

	buf, err := jws.Sign(jsc, jws.WithKey(jwa.PS256, pkey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func ReceiveLRNCredential(t *testing.T, leiCode string, vcID string, subjectID string) ([]byte, *VerifiableCredential) {
	client := http.Client{
		Timeout: 10 * time.Second,
	}

	vcID = url.PathEscape(vcID)
	subjectID = url.PathEscape(subjectID)

	//u := fmt.Sprintf("https://aerospace-digital-exchange.eu/notary/v2/registration-numbers/lei-code/%s?vcId=%s&subjectId=%s", leiCode, vcID, subjectID)
	u := fmt.Sprintf("https://gx-notary.gxdch.dih.telekom.com/v2/registration-numbers/lei-code/%s?vcId=%s&subjectId=%s", leiCode, vcID, subjectID)
	//u := fmt.Sprintf("https://www.delta-dao.com/notary/v2/registration-numbers/lei-code/%s?vcId=%s&subjectId=%s", leiCode, vcID, subjectID)
	//u := fmt.Sprintf("https://registrationnumber.notary.lab.gaia-x.eu/main/registration-numbers/lei-code/%s?vcId=%s&subjectId=%s", leiCode, vcID, subjectID)

	LRNRequest, err := http.NewRequest("GET", u, nil)
	if err != nil {
		t.Fatal(err)
	}
	LRNRequest.Header.Add("Accept", "application/vc+ld+jwt")
	do, err := client.Do(LRNRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer do.Body.Close()
	body, err := io.ReadAll(do.Body)
	if err != nil {
		t.Fatal(err)
	}

	LRNjwt, err := VCFromJWT(body)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	err = LRNjwt.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	return body, LRNjwt

}

func ReceiveVATIDCredential(t *testing.T, vatCode string, vcID string, subjectID string) ([]byte, *VerifiableCredential) {
	client := http.Client{
		Timeout: 10 * time.Second,
	}

	vcID = url.PathEscape(vcID)
	subjectID = url.PathEscape(subjectID)

	//u := fmt.Sprintf("https://aerospace-digital-exchange.eu/notary/v2/registration-numbers/lei-code/%s?vcId=%s&subjectId=%s", leiCode, vcID, subjectID)
	u := fmt.Sprintf("https://gx-notary.gxdch.dih.telekom.com/v2/registration-numbers/vat-id/%s?vcId=%s&subjectId=%s", vatCode, vcID, subjectID)
	//u := fmt.Sprintf("https://www.delta-dao.com/notary/v2/registration-numbers/lei-code/%s?vcId=%s&subjectId=%s", leiCode, vcID, subjectID)
	//u := fmt.Sprintf("https://registrationnumber.notary.lab.gaia-x.eu/main/registration-numbers/lei-code/%s?vcId=%s&subjectId=%s", leiCode, vcID, subjectID)

	LRNRequest, err := http.NewRequest("GET", u, nil)
	if err != nil {
		t.Fatal(err)
	}
	LRNRequest.Header.Add("Accept", "application/vc+ld+jwt")
	do, err := client.Do(LRNRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer do.Body.Close()
	body, err := io.ReadAll(do.Body)
	if err != nil {
		t.Fatal(err)
	}

	LRNjwt, err := VCFromJWT(body)
	if err != nil {
		t.Log(string(body))
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	err = LRNjwt.Verify()
	if err != nil {
		t.Fatal(err)
	}
	return body, LRNjwt

}
