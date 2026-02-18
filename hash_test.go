package outscript_test

import (
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
	"github.com/ModChain/secp256k1"
)

func TestOutHashP2WPKH(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	out := must(outscript.New(key.PubKey()).Out("p2wpkh"))
	h := out.Hash()
	if len(h) != 20 {
		t.Errorf("expected 20-byte hash, got %d", len(h))
	}
}

func TestOutHashP2PKH(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	out := must(outscript.New(key.PubKey()).Out("p2pkh"))
	h := out.Hash()
	if len(h) != 20 {
		t.Errorf("expected 20-byte hash, got %d", len(h))
	}
}

func TestOutHashP2PK(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	out := must(outscript.New(key.PubKey()).Out("p2pk"))
	h := out.Hash()
	if len(h) != 20 {
		t.Errorf("expected 20-byte hash (ripemd160), got %d", len(h))
	}
}

func TestOutHashP2SH(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	out := must(outscript.New(key.PubKey()).Out("p2sh:p2pkh"))

	// GuessOut will identify this as p2sh
	guessed := outscript.GuessOut(out.Bytes(), nil)
	h := guessed.Hash()
	if len(h) != 20 {
		t.Errorf("expected 20-byte hash for p2sh, got %d", len(h))
	}
}

func TestOutHashEth(t *testing.T) {
	out := must(outscript.ParseEvmAddress("0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7"))
	h := out.Hash()
	if len(h) != 20 {
		t.Errorf("expected 20-byte hash for eth, got %d", len(h))
	}
}

func TestOutHashUnknown(t *testing.T) {
	script := []byte{0x01, 0x02, 0x03}
	out := outscript.GuessOut(script, nil)
	h := out.Hash()
	if h != nil {
		t.Error("expected nil hash for invalid script")
	}
}
