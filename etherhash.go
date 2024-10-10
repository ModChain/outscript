package outscript

import (
	"hash"

	"golang.org/x/crypto/sha3"
)

type etherHash struct {
	h hash.Hash
}

func newEtherHash() hash.Hash {
	return &etherHash{}
}

func (e *etherHash) Reset() {
	e.h = nil
}

func (e *etherHash) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if e.h == nil {
		e.h = sha3.NewLegacyKeccak256()
		n, err := e.h.Write(b[1:])
		return n + 1, err
	}
	return e.h.Write(b)
}

func (e *etherHash) Sum(b []byte) []byte {
	return append(b, e.h.Sum(nil)[12:]...)
}

func (e *etherHash) Size() int {
	return 20
}

func (e *etherHash) BlockSize() int {
	if e.h != nil {
		return e.h.BlockSize()
	}
	return 136
}
