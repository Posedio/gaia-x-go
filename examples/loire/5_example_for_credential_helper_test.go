package loire

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Posedio/gaia-x-go/compliance"
	"github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// needs rework since the credential helper in the newest version has no field for custom endpoints
func TestCredentialHelperSignerServer(t *testing.T) {
	t.Log("Starting server")
	err := os.Setenv("TestSignPrivateKeyFilePath", "../../key.pem")
	if err != nil {
		t.Fatal(err)
	}

	path := os.Getenv("TestSignPrivateKeyFilePath")
	if path == "" {
		t.Fatal("missing env variable: TestSignPrivateKeyFilePath")
	}
	set, err := jwk.ReadFile(path, jwk.WithPEM(true))
	if err != nil {
		t.Fatal(err)
	}

	key, ok := set.Key(0)
	if !ok {
		t.Fatal("no key in set")
	}
	connector, err := compliance.NewComplianceConnector("", "", "loire", key, "did:web:did.dumss.me", "did:web:did.dumss.me#v2-2025")
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		all, err := io.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
			w.WriteHeader(500)
			return
		}

		var vcList []any
		vp := verifiableCredentials.NewEmptyVerifiablePresentationV2()

		err = json.Unmarshal(all, &vcList)
		if err != nil {
			log.Println(err)
			w.WriteHeader(500)
			return
		}

		for _, vc := range vcList {
			vj, err := json.Marshal(vc.(map[string]interface{}))
			if err != nil {
				log.Println(err)
				w.WriteHeader(500)
				return
			}
			v := verifiableCredentials.NewEmptyVerifiableCredential()
			err = json.Unmarshal(vj, v)
			if err != nil {
				log.Println(err)
				w.WriteHeader(500)
				return
			}
			err = connector.SelfSign(v)
			if err != nil {
				log.Println(err)
				w.WriteHeader(500)
				return
			}
			vp.AddEnvelopedVC(v.GetOriginalJWS())

		}

		err = connector.SelfSignPresentation(vp, 0)
		if err != nil {
			log.Println(err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
		w.Write(vp.GetOriginalJWS())

	})

	server := &http.Server{
		Addr:    ":3000",
		Handler: mux,
	}

	go server.ListenAndServe()
	time.Sleep(3 * time.Second)
	server.Shutdown(context.Background())

}
