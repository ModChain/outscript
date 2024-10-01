package outscript

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"github.com/KarpelesLab/cryptutil"
	"github.com/ModChain/secp256k1"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

type Out struct {
	Name   string `json:"name"`   // p2sh, etc
	Script string `json:"script"` // out script
	raw    []byte
}

func makeOut(name string, scriptPiece ...[]byte) *Out {
	v := slices.Concat(scriptPiece...)
	return &Out{
		Name:   name,
		Script: hex.EncodeToString(v),
		raw:    v,
	}
}

// GetOuts returns the potential outputs that can be opened in theory with the given pubkey. p2w* values are "pay to segwit" and
// can only be used on segwit-enabled chains.
func GetOuts(pubkey *secp256k1.PublicKey) []*Out {
	pubKeyComp := pubkey.SerializeCompressed()
	pubKeyUncomp := pubkey.SerializeUncompressed()
	pubKeyCompHash := cryptutil.Hash(pubKeyComp, sha256.New, ripemd160.New)
	pubKeyUncompHash := cryptutil.Hash(pubKeyComp, sha256.New, ripemd160.New)

	// https://learnmeabitcoin.com/technical/script/

	outScripts := []*Out{
		makeOut("p2pkh", []byte{0x76, 0xa9}, pushBytes(pubKeyCompHash), []byte{0x88, 0xac}),
		makeOut("p2pukh", []byte{0x76, 0xa9}, pushBytes(pubKeyUncompHash), []byte{0x88, 0xac}),
		makeOut("p2pk", pushBytes(pubKeyComp), []byte{0xac}),
		makeOut("p2puk", pushBytes(pubKeyUncomp), []byte{0xac}),
		makeOut("p2wpkh", []byte{0}, pushBytes(pubKeyCompHash)),
		makeOut("eth", cryptutil.Hash(pubKeyUncomp[1:], sha3.NewLegacyKeccak256)), // eth addr
	}

	for _, s := range outScripts {
		outScripts = append(outScripts, makeOut("p2sh:"+s.Name, []byte{0xa9}, pushBytes(cryptutil.Hash(s.raw, sha256.New, ripemd160.New)), []byte{0x87}))
		outScripts = append(outScripts, makeOut("p2wsh:"+s.Name, []byte{0}, pushBytes(cryptutil.Hash(s.raw, sha256.New))))
	}

	return outScripts
}
