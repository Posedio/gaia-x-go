package examples

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	//log.Println("Do stuff BEFORE the tests!")
	exit := m.Run()
	//log.Println("Do stuff AFTER the tests!")

	os.Exit(exit)
}
