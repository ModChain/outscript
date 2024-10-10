package outscript

import (
	"encoding/hex"

	"github.com/ModChain/secp256k1"
)

type Out struct {
	Name   string `json:"name"`   // p2sh, etc
	Script string `json:"script"` // out script
	raw    []byte
}

func (o *Out) Bytes() []byte {
	return o.raw
}

func (o *Out) String() string {
	return o.Name + ":" + o.Script
}

func makeOut(name string, script []byte) *Out {
	return &Out{
		Name:   name,
		Script: hex.EncodeToString(script),
		raw:    script,
	}
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
