package outscript

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"github.com/KarpelesLab/cryptutil"
	"github.com/ModChain/secp256k1"
	"golang.org/x/crypto/ripemd160"
)

type Out struct {
	Name   string   `json:"name"`            // p2sh, etc
	Script string   `json:"script"`          // out script
	Flags  []string `json:"flags,omitempty"` // flags
	raw    []byte
}

func (o *Out) Bytes() []byte {
	return o.raw
}

func (o *Out) String() string {
	return o.Name + ":" + o.Script
}

// Hash will extract the hash part of the Out, or return nil if there is no known hash
func (o *Out) Hash() []byte {
	switch o.Name {
	case "p2wpkh":
		return parsePushBytes(o.raw[1:])
	case "p2pkh", "p2pukh":
		return parsePushBytes(o.raw[2:])
	case "p2pk", "p2puk":
		return cryptutil.Hash(parsePushBytes(o.raw), sha256.New, ripemd160.New)
	case "eth":
		return o.raw
	default:
		return nil
	}
}

func makeOut(name string, script []byte, flags ...string) *Out {
	return &Out{
		Name:   name,
		Script: hex.EncodeToString(script),
		Flags:  flags,
		raw:    script,
	}
}

// GuessOut will return a out matching the provided script, and attempt to
// guess the correct type. pubkeyhint can be nil and this function will still
// be useful, but it won't be able to differenciate between compressed and
// uncompressed keys if the script contains a hashed key
func GuessOut(script []byte, pubkeyhint *secp256k1.PublicKey) *Out {
	if len(script) == 0 {
		return makeOut("empty", script, "invalid")
	}
	switch {
	case script[0] == 0:
		// Segwit
		switch len(script) {
		case 22:
			return makeOut("p2wpkh", script)
		case 34:
			return makeOut("p2wsh", script)
		default:
			return makeOut("invalid", script)
		}
	case script[0] == 0x6a: // OP_RETURN
		return makeOut("op_return", script)
	case script[len(script)-1] == 0xac: // OP_CHECKSIG
		if len(script) == 25 && bytes.HasPrefix(script, []byte{0x76, 0xa9, 0x14}) && bytes.HasSuffix(script, []byte{0x88, 0xac}) {
			// pay-to-keyhash
			if pubkeyhint == nil {
				return makeOut("p2pkh", script)
			}
			s := New(pubkeyhint)
			for _, e := range []string{"p2pkh", "p2pukh"} {
				if bytes.Equal(s.Out(e).Bytes(), script) {
					return makeOut(e, script)
				}
			}
			// could not identify the script
			return makeOut("p2pkh", script)
		}
		v := parsePushBytes(script)
		if v != nil && bytes.Equal(append(pushBytes(v), 0xac), script) {
			switch len(v) {
			case 33:
				return makeOut("p2pk", script)
			case 65:
				return makeOut("p2puk", script)
			}
		}
	case script[len(script)-1] == 0x87: // OP_EQUAL (likely P2SH)
		v := parsePushBytes(script[1:])
		if v != nil && bytes.Equal(slices.Concat([]byte{0xa9}, pushBytes(v), []byte{0x87}), script) {
			// p2sh
			if pubkeyhint == nil {
				return makeOut("p2sh", script)
			}
			s := New(pubkeyhint)
			for _, e := range []string{"p2sh:p2pk", "p2sh:p2pkh", "p2sh:p2puk", "p2sh:p2pukh", "p2sh:p2wpkh"} {
				if bytes.Equal(s.Out(e).Bytes(), script) {
					return makeOut(e, script)
				}
			}
			// could not identify the script
			return makeOut("p2sh", script)
		}
	}

	// unrecognized
	return makeOut("invalid", script)
}

// GetOuts returns the potential outputs that can be opened in theory with the given pubkey. p2w* values are "pay to segwit" and
// can only be used on segwit-enabled chains.
func GetOuts(pubkey *secp256k1.PublicKey) []*Out {
	v := New(pubkey)

	// https://learnmeabitcoin.com/technical/script/

	var outScripts []*Out
	for name := range Formats {
		outScripts = append(outScripts, v.Out(name))
	}

	return outScripts
}
