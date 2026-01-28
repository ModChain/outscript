package outscript

import (
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/KarpelesLab/cryptutil"
	"golang.org/x/crypto/ripemd160"
)

// IHashInfo is an [Insertable] that hashes the output of another [Insertable] using one
// or more chained hash functions.
type IHashInfo struct {
	v    Insertable
	hash []func() hash.Hash
}

func (i IHashInfo) Bytes(s *Script) ([]byte, error) {
	v, err := i.v.Bytes(s)
	if err != nil {
		return nil, err
	}
	return cryptutil.Hash(v, i.hash...), nil
}

func (i IHashInfo) String() string {
	return fmt.Sprintf("Hash(%s, %v)", i.v, i.hash)
}

// IHash returns an [IHashInfo] that hashes the output of v using the given hash functions in sequence.
func IHash(v Insertable, hash ...func() hash.Hash) IHashInfo {
	return IHashInfo{v: v, hash: hash}
}

// IHash160 returns an [IHashInfo] that computes HASH160 (SHA-256 followed by RIPEMD-160) of the
// output of v.
func IHash160(v Insertable) IHashInfo {
	return IHash(v, sha256.New, ripemd160.New)
}
