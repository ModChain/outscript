package outscript

import "encoding/hex"

// Insertable is a component that can produce bytes for inclusion in an output script.
// Implementations include literal [Bytes], [Lookup] references to other formats,
// [IPushBytes] for Bitcoin PUSHDATA encoding, and [IHashInfo] for hashing.
type Insertable interface {
	Bytes(*Script) ([]byte, error)
	String() string
}

// Bytes is an [Insertable] that returns a fixed byte sequence.
type Bytes []byte

// Bytes returns the literal byte sequence.
func (b Bytes) Bytes(*Script) ([]byte, error) {
	return []byte(b), nil
}

// String returns the hex encoding of the byte sequence.
func (b Bytes) String() string {
	return hex.EncodeToString(b)
}

// Lookup is an [Insertable] that generates bytes by looking up another named format
// via [Script.Generate].
type Lookup string

// Bytes generates bytes by looking up the named format on the given Script.
func (l Lookup) Bytes(s *Script) ([]byte, error) {
	return s.Generate(string(l))
}

// String returns the lookup name.
func (l Lookup) String() string {
	return string(l)
}
