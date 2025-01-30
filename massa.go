package outscript

import (
	"hash"

	"lukechampine.com/blake3"
)

func newMassaHash() hash.Hash {
	return blake3.New(32, nil)
}
