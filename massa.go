package outscript

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"hash"
	"slices"
	"strings"

	"github.com/KarpelesLab/cryptutil"
	"github.com/ModChain/base58"
	"lukechampine.com/blake3"
)

func newMassaHash() hash.Hash {
	return blake3.New(32, nil)
}

func ParseMassaAddress(address string) (*Out, error) {
	if !strings.HasPrefix(address, "AU") && !strings.HasPrefix(address, "AS") {
		return nil, errors.New("Massa must start with AU or AS")
	}

	var typ byte
	switch address[1] {
	case 'U':
		typ = 0
	case 'S':
		typ = 1
	}

	// decode base58 code
	buf, err := base58.Bitcoin.Decode(address[2:])
	if err == nil {
		// check hash
		chk := buf[len(buf)-4:]
		buf = buf[:len(buf)-4]
		h := cryptutil.Hash(buf, sha256.New, sha256.New)
		if subtle.ConstantTimeCompare(h[:4], chk) != 1 {
			err = errors.New("bad checksum")
		}
	}

	// prepend typ
	buf = slices.Concat([]byte{typ}, buf)

	// all good
	return &Out{Name: "massa", Script: hex.EncodeToString(buf), raw: buf, Flags: []string{"massa"}}, nil
}
