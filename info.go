package outscript

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"github.com/KarpelesLab/cryptutil"
	"github.com/ModChain/secp256k1"
	"golang.org/x/crypto/ripemd160"
)

type Info struct {
	Name   string `json:"name"`   // p2sh, etc
	Script string `json:"script"` // out script
	raw    []byte
}

func makeInfo(name string, scriptPiece ...[]byte) *Info {
	v := slices.Concat(scriptPiece...)
	return &Info{
		Name:   name,
		Script: hex.EncodeToString(v),
		raw:    v,
	}
}

// GetOutputs returns the potential outputs that can be opened in theory with the given pubkey. p2w* values are "pay to segwit" and
// can only be used on segwit-enabled chains.
func GetOutputs(pubkey *secp256k1.PublicKey) []*Info {
	pubKeyComp := pubkey.SerializeCompressed()
	pubKeyUncomp := pubkey.SerializeUncompressed()
	pubKeyCompHash := cryptutil.Hash(pubKeyComp, sha256.New, ripemd160.New)
	pubKeyUncompHash := cryptutil.Hash(pubKeyComp, sha256.New, ripemd160.New)

	// https://learnmeabitcoin.com/technical/script/

	outScripts := []*Info{
		makeInfo("p2pkh", []byte{0x76, 0xa9}, pushBytes(pubKeyCompHash), []byte{0x88, 0xac}),
		makeInfo("p2pukh", []byte{0x76, 0xa9}, pushBytes(pubKeyUncompHash), []byte{0x88, 0xac}),
		makeInfo("p2pk", pushBytes(pubKeyComp), []byte{0xac}),
		makeInfo("p2puk", pushBytes(pubKeyUncomp), []byte{0xac}),
		makeInfo("p2wpkh", []byte{0}, pushBytes(pubKeyCompHash)),
	}

	for _, s := range outScripts {
		outScripts = append(outScripts, makeInfo("p2sh:"+s.Name, []byte{0xa9}, pushBytes(cryptutil.Hash(s.raw, sha256.New, ripemd160.New)), []byte{0x87}))
		outScripts = append(outScripts, makeInfo("p2wsh:"+s.Name, []byte{0}, pushBytes(cryptutil.Hash(s.raw, sha256.New))))
	}

	return outScripts
}
