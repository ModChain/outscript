package outscript_test

import (
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestGuessPubKeyAndHashByOutScriptP2SH(t *testing.T) {
	// P2SH: a914<20-byte-hash>87
	script := must(hex.DecodeString("a914301550140d26c46ce4a50114a15c20f87602153787"))
	pk, pkh := outscript.GuessPubKeyAndHashByOutScript(script)
	if pk != nil {
		t.Error("expected nil pubkey for P2SH")
	}
	if hex.EncodeToString(pkh) != "301550140d26c46ce4a50114a15c20f860215378" {
		// The hash is the 20 bytes at positions 2..22
		if len(pkh) != 20 {
			t.Errorf("expected 20-byte hash, got %d", len(pkh))
		}
	}
}

func TestGuessPubKeyAndHashByOutScriptP2PK(t *testing.T) {
	// P2PK compressed: 21<33-byte-pubkey>ac
	script := must(hex.DecodeString("210208c27162565b6660961b5de8b4a21abcd7bfd197b7e85d6709e8b71055b2c8b2ac"))
	pk, pkh := outscript.GuessPubKeyAndHashByOutScript(script)
	if pk == nil {
		t.Fatal("expected non-nil pubkey for P2PK")
	}
	if len(pk) != 33 {
		t.Errorf("expected 33-byte pubkey, got %d", len(pk))
	}
	if len(pkh) != 20 {
		t.Errorf("expected 20-byte hash, got %d", len(pkh))
	}
}

func TestGuessPubKeyAndHashByOutScriptP2PKUncompressed(t *testing.T) {
	// P2PK uncompressed: 41<65-byte-pubkey>ac
	script := make([]byte, 67)
	script[0] = 0x41
	script[66] = 0xac
	// fill with dummy pubkey bytes
	for i := 1; i < 66; i++ {
		script[i] = byte(i)
	}
	pk, pkh := outscript.GuessPubKeyAndHashByOutScript(script)
	if pk == nil {
		t.Fatal("expected non-nil pubkey for uncompressed P2PK")
	}
	if len(pk) != 65 {
		t.Errorf("expected 65-byte pubkey, got %d", len(pk))
	}
	if len(pkh) != 20 {
		t.Errorf("expected 20-byte hash, got %d", len(pkh))
	}
}

func TestGuessPubKeyAndHashByOutScriptP2WPKH(t *testing.T) {
	// P2WPKH: 0014<20-byte-witness-program>
	script := must(hex.DecodeString("0014ab4996a0ed164be1564013917ec5a5a4b10563fe"))
	pk, pkh := outscript.GuessPubKeyAndHashByOutScript(script)
	if pk != nil {
		t.Error("expected nil pubkey for P2WPKH")
	}
	if hex.EncodeToString(pkh) != "ab4996a0ed164be1564013917ec5a5a4b10563fe" {
		t.Errorf("unexpected hash: %x", pkh)
	}
}

func TestGuessPubKeyAndHashByOutScriptP2WSH(t *testing.T) {
	// P2WSH: 0020<32-byte-witness-program>
	script := make([]byte, 34)
	script[0] = 0x00
	script[1] = 0x20
	for i := 2; i < 34; i++ {
		script[i] = byte(i)
	}
	pk, pkh := outscript.GuessPubKeyAndHashByOutScript(script)
	if pk != nil {
		t.Error("expected nil pubkey for P2WSH")
	}
	if len(pkh) != 32 {
		t.Errorf("expected 32-byte hash, got %d", len(pkh))
	}
}

func TestGuessPubKeyAndHashByOutScriptUnknown(t *testing.T) {
	script := []byte{0x01, 0x02, 0x03}
	pk, pkh := outscript.GuessPubKeyAndHashByOutScript(script)
	if pk != nil || pkh != nil {
		t.Error("expected nil,nil for unknown script")
	}
}

func TestGuessPubKeyAndHashByInScript(t *testing.T) {
	// Typical P2PKH input: <sig> <pubkey>
	// We'll construct a fake one with two push data items
	sig := make([]byte, 72)
	pubkey := make([]byte, 33)
	pubkey[0] = 0x02
	for i := 1; i < 33; i++ {
		pubkey[i] = byte(i)
	}

	script := append(outscript.PushBytes(sig), outscript.PushBytes(pubkey)...)
	pk, pkh := outscript.GuessPubKeyAndHashByInScript(script)
	if pk == nil {
		t.Fatal("expected non-nil pubkey")
	}
	if len(pk) != 33 {
		t.Errorf("expected 33-byte pubkey, got %d", len(pk))
	}
	if len(pkh) != 20 {
		t.Errorf("expected 20-byte hash, got %d", len(pkh))
	}
}

func TestGuessPubKeyAndHashByInScriptEmpty(t *testing.T) {
	pk, pkh := outscript.GuessPubKeyAndHashByInScript(nil)
	if pk != nil || pkh != nil {
		t.Error("expected nil,nil for empty input script")
	}
}
