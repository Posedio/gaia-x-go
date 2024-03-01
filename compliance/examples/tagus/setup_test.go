package loire

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	//log.Println("Do stuff BEFORE the tests!")
	exit := m.Run()
	//log.Println("Do stuff AFTER the tests!")

	os.Exit(exit)
}

// helper function to get the private key from certificate file
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
