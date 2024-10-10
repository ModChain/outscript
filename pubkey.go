package outscript

import "fmt"

type PubKeyInsert int

const (
	IPubKeyComp PubKeyInsert = iota
	IPubKey
)

func (pk PubKeyInsert) Bytes(s *Script) []byte {
	switch pk {
	case IPubKeyComp:
		return s.pubKeyComp
	case IPubKey:
		return s.pubKeyUncomp
	default:
		panic("invalid value for PubKeyInsert")
	}
}

func (pk PubKeyInsert) String() string {
	switch pk {
	case IPubKeyComp:
		return "PubKey(compressed)"
	case IPubKey:
		return "PubKey(uncompressed)"
	default:
		return fmt.Sprintf("PubKeyInsert(%d)", pk)
	}
}
