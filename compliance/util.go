/*
MIT License
Copyright (c) 2023-2025 Stefan Dumss, MIVP TU Wien
Copyright (c) 2025 Stefan Dumss, Posedio GmbH
*/

package compliance

import (
	"crypto/sha256"
	"fmt"
)

// hash256 returns the sha256 hex representation of the given byte slice
func hash256(sd []byte) string {
	h := sha256.New()
	h.Write(sd)

	ha := h.Sum(nil)

	hash := fmt.Sprintf("%x", ha)
	return hash
}
