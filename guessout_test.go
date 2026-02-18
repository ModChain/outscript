package outscript_test

import (
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
	"github.com/ModChain/secp256k1"
)

func TestGuessOutP2PKH(t *testing.T) {
	script := must(hex.DecodeString("76a9149e8985f82bc4e0f753d0492aa8d11cc39925774088ac"))
	out := outscript.GuessOut(script, nil)
	if out.Name != "p2pkh" {
		t.Errorf("expected p2pkh, got %s", out.Name)
	}
}

func TestGuessOutP2PKHWithHint(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	script := must(outscript.New(key.PubKey()).Generate("p2pkh"))
	out := outscript.GuessOut(script, key.PubKey())
	if out.Name != "p2pkh" {
		t.Errorf("expected p2pkh, got %s", out.Name)
	}
}

func TestGuessOutP2PUKH(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	script := must(outscript.New(key.PubKey()).Generate("p2pukh"))
	out := outscript.GuessOut(script, key.PubKey())
	if out.Name != "p2pukh" {
		t.Errorf("expected p2pukh, got %s", out.Name)
	}
}

func TestGuessOutP2PK(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	script := must(outscript.New(key.PubKey()).Generate("p2pk"))
	out := outscript.GuessOut(script, nil)
	if out.Name != "p2pk" {
		t.Errorf("expected p2pk, got %s", out.Name)
	}
}

func TestGuessOutP2PUK(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	script := must(outscript.New(key.PubKey()).Generate("p2puk"))
	out := outscript.GuessOut(script, nil)
	if out.Name != "p2puk" {
		t.Errorf("expected p2puk, got %s", out.Name)
	}
}

func TestGuessOutP2SH(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	script := must(outscript.New(key.PubKey()).Generate("p2sh:p2pkh"))
	out := outscript.GuessOut(script, nil)
	if out.Name != "p2sh" {
		t.Errorf("expected p2sh, got %s", out.Name)
	}
}

func TestGuessOutP2SHWithHint(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	script := must(outscript.New(key.PubKey()).Generate("p2sh:p2wpkh"))
	out := outscript.GuessOut(script, key.PubKey())
	if out.Name != "p2sh:p2wpkh" {
		t.Errorf("expected p2sh:p2wpkh, got %s", out.Name)
	}
}

func TestGuessOutP2WPKH(t *testing.T) {
	script := must(hex.DecodeString("0014ab4996a0ed164be1564013917ec5a5a4b10563fe"))
	out := outscript.GuessOut(script, nil)
	if out.Name != "p2wpkh" {
		t.Errorf("expected p2wpkh, got %s", out.Name)
	}
}

func TestGuessOutP2WSH(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	script := must(outscript.New(key.PubKey()).Generate("p2wsh:p2pkh"))
	out := outscript.GuessOut(script, nil)
	if out.Name != "p2wsh" {
		t.Errorf("expected p2wsh, got %s", out.Name)
	}
}

func TestGuessOutEmpty(t *testing.T) {
	out := outscript.GuessOut(nil, nil)
	if out.Name != "empty" {
		t.Errorf("expected empty, got %s", out.Name)
	}
}

func TestGuessOutOpReturn(t *testing.T) {
	script := must(hex.DecodeString("6a0b68656c6c6f20776f726c64"))
	out := outscript.GuessOut(script, nil)
	if out.Name != "op_return" {
		t.Errorf("expected op_return, got %s", out.Name)
	}
}

func TestGuessOutInvalid(t *testing.T) {
	script := []byte{0x01, 0x02, 0x03}
	out := outscript.GuessOut(script, nil)
	if out.Name != "invalid" {
		t.Errorf("expected invalid, got %s", out.Name)
	}
}
