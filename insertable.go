package outscript

import "encoding/hex"

type Insertable interface {
	Bytes(*Script) ([]byte, error)
	String() string
}

type Bytes []byte

func (b Bytes) Bytes(*Script) ([]byte, error) {
	return []byte(b), nil
}

func (b Bytes) String() string {
	return hex.EncodeToString(b)
}

type Lookup string

func (l Lookup) Bytes(s *Script) ([]byte, error) {
	return s.Generate(string(l))
}

func (l Lookup) String() string {
	return string(l)
}
