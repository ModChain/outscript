package outscript

import (
	"slices"

	"github.com/ModChain/secp256k1"
)

type Script struct {
	pubkey       *secp256k1.PublicKey
	pubKeyComp   []byte
	pubKeyUncomp []byte
}

func New(pubkey *secp256k1.PublicKey) *Script {
	v := &Script{
		pubkey:       pubkey,
		pubKeyComp:   pubkey.SerializeCompressed(),
		pubKeyUncomp: pubkey.SerializeUncompressed(),
	}

	return v
}

func (s *Script) generate(name string) []byte {
	f, ok := Formats[name]
	if !ok {
		return nil
	}

	var pieces [][]byte

	for _, piece := range f {
		pieces = append(pieces, piece.Bytes(s))
	}
	return slices.Concat(pieces...)
}

func (s *Script) Out(name string) *Out {
	f, ok := Formats[name]
	if !ok {
		return nil
	}

	var pieces [][]byte

	for _, piece := range f {
		pieces = append(pieces, piece.Bytes(s))
	}
	return makeOut(name, pieces...)
}
