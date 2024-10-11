package outscript

import (
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/KarpelesLab/cryptutil"
	"golang.org/x/crypto/ripemd160"
)

type IHashInfo struct {
	v    Insertable
	hash []func() hash.Hash
}

func (i IHashInfo) Bytes(s *Script) []byte {
	return cryptutil.Hash(i.v.Bytes(s), i.hash...)
}

func (i IHashInfo) String() string {
	return fmt.Sprintf("Hash(%s, %v)", i.v, i.hash)
}

func IHash(v Insertable, hash ...func() hash.Hash) IHashInfo {
	return IHashInfo{v: v, hash: hash}
}

func IHash160(v Insertable) IHashInfo {
	return IHash(v, sha256.New, ripemd160.New)
}