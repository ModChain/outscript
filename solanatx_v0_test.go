package outscript_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestSolanaTxV0Basic(t *testing.T) {
	seed := must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88"))
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	var from outscript.SolanaKey
	copy(from[:], pub)

	to := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	blockhash := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))

	ix := outscript.SolanaTransferInstruction(from, to, 1000000)
	tx, err := outscript.NewSolanaTxV0(from, blockhash, nil, ix)
	if err != nil {
		t.Fatalf("NewSolanaTxV0 failed: %s", err)
	}

	if tx.MessageV0 == nil {
		t.Fatal("expected MessageV0 to be set")
	}
	if tx.MessageV0.Header.NumRequiredSignatures != 1 {
		t.Errorf("expected 1 signer, got %d", tx.MessageV0.Header.NumRequiredSignatures)
	}

	// Sign
	if err := tx.Sign(key); err != nil {
		t.Fatalf("sign failed: %s", err)
	}

	// Verify
	if err := tx.Verify(); err != nil {
		t.Fatalf("verify failed: %s", err)
	}

	// Hash
	h, err := tx.Hash()
	if err != nil {
		t.Fatalf("hash failed: %s", err)
	}
	if len(h) != 64 {
		t.Errorf("expected 64-byte hash, got %d", len(h))
	}
}

func TestSolanaTxV0RoundTrip(t *testing.T) {
	seed := must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88"))
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	var from outscript.SolanaKey
	copy(from[:], pub)

	to := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	blockhash := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))

	ix := outscript.SolanaTransferInstruction(from, to, 500000)
	tx, err := outscript.NewSolanaTxV0(from, blockhash, nil, ix)
	if err != nil {
		t.Fatalf("NewSolanaTxV0 failed: %s", err)
	}

	if err := tx.Sign(key); err != nil {
		t.Fatalf("sign failed: %s", err)
	}

	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	var tx2 outscript.SolanaTx
	if err := tx2.UnmarshalBinary(data); err != nil {
		t.Fatalf("unmarshal failed: %s", err)
	}

	// Should be detected as v0
	if tx2.MessageV0 == nil {
		t.Fatal("expected MessageV0 to be set after unmarshal")
	}

	// Verify signatures match
	if len(tx2.Signatures) != len(tx.Signatures) {
		t.Fatalf("signature count mismatch: %d != %d", len(tx2.Signatures), len(tx.Signatures))
	}
	for i := range tx.Signatures {
		if !bytes.Equal(tx.Signatures[i], tx2.Signatures[i]) {
			t.Errorf("signature %d mismatch", i)
		}
	}

	// Verify message fields
	if tx2.MessageV0.Header != tx.MessageV0.Header {
		t.Error("header mismatch")
	}
	if len(tx2.MessageV0.AccountKeys) != len(tx.MessageV0.AccountKeys) {
		t.Fatalf("account keys count mismatch")
	}
	for i := range tx.MessageV0.AccountKeys {
		if tx2.MessageV0.AccountKeys[i] != tx.MessageV0.AccountKeys[i] {
			t.Errorf("account key %d mismatch", i)
		}
	}
	if tx2.MessageV0.RecentBlockhash != tx.MessageV0.RecentBlockhash {
		t.Error("blockhash mismatch")
	}

	// Verify round-trip
	if err := tx2.Verify(); err != nil {
		t.Fatalf("verify after round-trip failed: %s", err)
	}

	// Byte-for-byte equality
	data2, err := tx2.MarshalBinary()
	if err != nil {
		t.Fatalf("re-marshal failed: %s", err)
	}
	if !bytes.Equal(data, data2) {
		t.Error("re-serialized bytes differ from original")
	}
}

func TestSolanaTxV0WithLookups(t *testing.T) {
	seed := must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88"))
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	var from outscript.SolanaKey
	copy(from[:], pub)

	to := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	blockhash := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))
	altKey := must(outscript.ParseSolanaKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"))

	lookups := []outscript.SolanaAddressTableLookup{
		{
			AccountKey:      altKey,
			WritableIndexes: []uint8{0, 1},
			ReadonlyIndexes: []uint8{2, 3, 4},
		},
	}

	ix := outscript.SolanaTransferInstruction(from, to, 1000000)
	tx, err := outscript.NewSolanaTxV0(from, blockhash, lookups, ix)
	if err != nil {
		t.Fatalf("NewSolanaTxV0 failed: %s", err)
	}

	if len(tx.MessageV0.AddressTableLookups) != 1 {
		t.Fatalf("expected 1 lookup, got %d", len(tx.MessageV0.AddressTableLookups))
	}
	if !bytes.Equal(tx.MessageV0.AddressTableLookups[0].WritableIndexes, []uint8{0, 1}) {
		t.Error("writable indexes mismatch")
	}
	if !bytes.Equal(tx.MessageV0.AddressTableLookups[0].ReadonlyIndexes, []uint8{2, 3, 4}) {
		t.Error("readonly indexes mismatch")
	}

	if err := tx.Sign(key); err != nil {
		t.Fatalf("sign failed: %s", err)
	}

	// Round-trip
	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	var tx2 outscript.SolanaTx
	if err := tx2.UnmarshalBinary(data); err != nil {
		t.Fatalf("unmarshal failed: %s", err)
	}

	if tx2.MessageV0 == nil {
		t.Fatal("expected v0 after unmarshal")
	}
	if len(tx2.MessageV0.AddressTableLookups) != 1 {
		t.Fatalf("expected 1 lookup after unmarshal, got %d", len(tx2.MessageV0.AddressTableLookups))
	}
	if !bytes.Equal(tx2.MessageV0.AddressTableLookups[0].WritableIndexes, []uint8{0, 1}) {
		t.Error("writable indexes mismatch after unmarshal")
	}
	if !bytes.Equal(tx2.MessageV0.AddressTableLookups[0].ReadonlyIndexes, []uint8{2, 3, 4}) {
		t.Error("readonly indexes mismatch after unmarshal")
	}

	// Byte-for-byte
	data2, err := tx2.MarshalBinary()
	if err != nil {
		t.Fatalf("re-marshal failed: %s", err)
	}
	if !bytes.Equal(data, data2) {
		t.Error("re-serialized bytes differ")
	}
}

func TestSolanaTxV0VersionDetection(t *testing.T) {
	// Legacy transaction should NOT have MessageV0 set after unmarshal.
	seed := must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88"))
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	var from outscript.SolanaKey
	copy(from[:], pub)

	to := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	blockhash := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))

	ix := outscript.SolanaTransferInstruction(from, to, 1000000)

	// Legacy transaction
	legacyTx, err := outscript.NewSolanaTx(from, blockhash, ix)
	if err != nil {
		t.Fatalf("NewSolanaTx failed: %s", err)
	}
	if err := legacyTx.Sign(key); err != nil {
		t.Fatalf("sign failed: %s", err)
	}
	legacyData, err := legacyTx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	var legacyTx2 outscript.SolanaTx
	if err := legacyTx2.UnmarshalBinary(legacyData); err != nil {
		t.Fatalf("unmarshal failed: %s", err)
	}
	if legacyTx2.MessageV0 != nil {
		t.Error("legacy transaction should not have MessageV0 set")
	}

	// V0 transaction
	v0Tx, err := outscript.NewSolanaTxV0(from, blockhash, nil, ix)
	if err != nil {
		t.Fatalf("NewSolanaTxV0 failed: %s", err)
	}
	if err := v0Tx.Sign(key); err != nil {
		t.Fatalf("sign failed: %s", err)
	}
	v0Data, err := v0Tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	var v0Tx2 outscript.SolanaTx
	if err := v0Tx2.UnmarshalBinary(v0Data); err != nil {
		t.Fatalf("unmarshal failed: %s", err)
	}
	if v0Tx2.MessageV0 == nil {
		t.Error("v0 transaction should have MessageV0 set")
	}

	// They should produce different wire bytes (v0 has version prefix)
	if bytes.Equal(legacyData, v0Data) {
		t.Error("legacy and v0 should have different wire formats")
	}
}

func TestSolanaTxV0MultipleLookups(t *testing.T) {
	feePayer := must(outscript.ParseSolanaKey("11111111111111111111111111111111"))
	blockhash := must(outscript.ParseSolanaKey("11111111111111111111111111111111"))
	alt1 := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	alt2 := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))

	lookups := []outscript.SolanaAddressTableLookup{
		{AccountKey: alt1, WritableIndexes: []uint8{0}, ReadonlyIndexes: []uint8{1}},
		{AccountKey: alt2, WritableIndexes: nil, ReadonlyIndexes: []uint8{0, 1, 2}},
	}

	tx, err := outscript.NewSolanaTxV0(feePayer, blockhash, lookups)
	if err != nil {
		t.Fatalf("NewSolanaTxV0 failed: %s", err)
	}

	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	var tx2 outscript.SolanaTx
	if err := tx2.UnmarshalBinary(data); err != nil {
		t.Fatalf("unmarshal failed: %s", err)
	}

	if len(tx2.MessageV0.AddressTableLookups) != 2 {
		t.Fatalf("expected 2 lookups, got %d", len(tx2.MessageV0.AddressTableLookups))
	}
	if tx2.MessageV0.AddressTableLookups[0].AccountKey != alt1 {
		t.Error("first lookup key mismatch")
	}
	if tx2.MessageV0.AddressTableLookups[1].AccountKey != alt2 {
		t.Error("second lookup key mismatch")
	}
	if len(tx2.MessageV0.AddressTableLookups[1].ReadonlyIndexes) != 3 {
		t.Errorf("expected 3 readonly indexes, got %d", len(tx2.MessageV0.AddressTableLookups[1].ReadonlyIndexes))
	}

	data2, err := tx2.MarshalBinary()
	if err != nil {
		t.Fatalf("re-marshal failed: %s", err)
	}
	if !bytes.Equal(data, data2) {
		t.Error("round-trip bytes differ")
	}
}
