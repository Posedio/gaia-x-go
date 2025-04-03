package loire

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
	"log"
	"os"
	"testing"
)

var key jwk.Key

func TestMain(m *testing.M) {
	key = getKey()
	exit := m.Run()
	os.Exit(exit)
}

// helper function to get the private key from certificate file
func getKey() jwk.Key {

	//todo remove
	err := os.Setenv("TestSignPrivateKeyFilePath", "../../key.pem")
	if err != nil {
		log.Fatal(err)
	}
	path := os.Getenv("TestSignPrivateKeyFilePath")
	if path == "" {
		log.Fatal("missing env variable: TestSignPrivateKeyFilePath")
	}
	set, err := jwk.ReadFile(path, jwk.WithPEM(true))
	if err != nil {
		log.Fatal(err)
	}

	key, ok := set.Key(0)
	if !ok {
		log.Fatal("no key in set")
	}
	return key
}
