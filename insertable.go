package outscript

import "encoding/hex"

type Insertable interface {
	Bytes(*Script) []byte
	String() string
}

type Bytes []byte

func (b Bytes) Bytes(*Script) []byte {
	return []byte(b)
}

func (b Bytes) String() string {
	return hex.EncodeToString(b)
}

type Lookup string

func (l Lookup) Bytes(s *Script) []byte {
	return s.Generate(string(l))
}

func (l Lookup) String() string {
	return string(l)
}
