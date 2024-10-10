package outscript

import (
	"slices"

	"github.com/ModChain/secp256k1"
)

type Script struct {
	pubkey       *secp256k1.PublicKey
	pubKeyComp   []byte
	pubKeyUncomp []byte
	cache        map[string][]byte
}

// New returns a new [Script] object for the given public key, which can be used to generate output scripts
func New(pubkey *secp256k1.PublicKey) *Script {
	v := &Script{
		pubkey:       pubkey,
		pubKeyComp:   pubkey.SerializeCompressed(),
		pubKeyUncomp: pubkey.SerializeUncompressed(),
		cache:        make(map[string][]byte),
	}

	return v
}

// Generate will return the byte value for the specified script type for the current public key
func (s *Script) Generate(name string) []byte {
	if r, ok := s.cache[name]; ok {
		return r
	}
	f, ok := Formats[name]
	if !ok {
		return nil
	}

	var pieces [][]byte

	for _, piece := range f {
		pieces = append(pieces, piece.Bytes(s))
	}
	res := slices.Concat(pieces...)
	s.cache[name] = res
	return res
}

// Out returns a [Out] object matching the requested script
func (s *Script) Out(name string) *Out {
	_, ok := Formats[name]
	if !ok {
		return nil
	}

	return makeOut(name, s.Generate(name))
}
