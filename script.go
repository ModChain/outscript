package outscript

import (
	"crypto"
	"fmt"
	"slices"
)

type Script struct {
	pubkey crypto.PublicKey
	cache  map[string][]byte
}

// New returns a new [Script] object for the given public key, which can be used to generate output scripts
func New(pubkey crypto.PublicKey) *Script {
	v := &Script{
		pubkey: pubkey,
		cache:  make(map[string][]byte),
	}

	return v
}

// getPubKeyBytes returns the public key in the requested format (one of pubkey, pubkey:comp or pubkey:uncomp).
// pubkey:comp and pubkey:uncomp require a secp256k1 key
func (s *Script) getPubKeyBytes(typ string) ([]byte, error) {
	switch typ {
	case "pubkey:comp":
		if o, ok := s.pubkey.(interface{ SerializeCompressed() []byte }); ok {
			return o.SerializeCompressed(), nil
		}
		return nil, fmt.Errorf("pubkey of type %T does not support %s export", s.pubkey, typ)
	case "pubkey:uncomp":
		if o, ok := s.pubkey.(interface{ SerializeUncompressed() []byte }); ok {
			return o.SerializeUncompressed(), nil
		}
		return nil, fmt.Errorf("pubkey of type %T does not support %s export", s.pubkey, typ)
	default:
		return nil, fmt.Errorf("unknown public key format %s", typ)
	}
}

// Generate will return the byte value for the specified script type for the current public key
func (s *Script) Generate(name string) ([]byte, error) {
	if r, ok := s.cache[name]; ok {
		return r, nil
	}

	// some special cases to access the public key
	switch name {
	case "pubkey", "pubkey:comp", "pubkey:uncomp":
		res, err := s.getPubKeyBytes(name)
		if err != nil {
			return nil, err
		}
		s.cache[name] = res
		return res, nil
	}

	f, ok := Formats[name]
	if !ok {
		return nil, fmt.Errorf("unsupported format %s", name)
	}

	var pieces [][]byte

	for _, piece := range f {
		v, err := piece.Bytes(s)
		if err != nil {
			return nil, err
		}
		pieces = append(pieces, v)
	}
	res := slices.Concat(pieces...)
	s.cache[name] = res
	return res, nil
}

// Out returns a [Out] object matching the requested script
func (s *Script) Out(name string) (*Out, error) {
	buf, err := s.Generate(name)
	if err != nil {
		return nil, err
	}

	return makeOut(name, buf), nil
}
