package outscript

import (
	"encoding/hex"

	"github.com/BottleFmt/gobottle"
	"golang.org/x/crypto/sha3"
)

func eip55(in []byte) string {
	buf := make([]byte, hex.EncodedLen(len(in))+2)
	buf[0] = '0'
	buf[1] = 'x'
	hex.Encode(buf[2:], in)
	a := buf[2:]

	hash := gobottle.Hash(a, sha3.NewLegacyKeccak256)

	for i := range a {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if a[i] > '9' && hashByte > 7 {
			a[i] -= 32
		}
	}
	return string(buf)
}
