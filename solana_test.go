package outscript_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestSolanaAddress(t *testing.T) {
	key := ed25519.NewKeyFromSeed(must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88")))
	s := outscript.New(key.Public())

	sout, err := s.Out("solana")
	if err != nil {
		t.Fatalf("failed to generate solana out: %s", err)
	}

	addr, err := sout.Address("solana")
	if err != nil {
		t.Fatalf("failed to generate solana address: %s", err)
	}

	// Round-trip: parse the address and verify it matches.
	parsed, err := outscript.ParseSolanaAddress(addr)
	if err != nil {
		t.Fatalf("failed to parse solana address %s: %s", addr, err)
	}
	if parsed.Script != sout.Script {
		t.Errorf("round-trip failed: scripts differ: %s != %s", parsed.Script, sout.Script)
	}

	// Verify Hash() returns the raw bytes.
	h := sout.Hash()
	if h == nil {
		t.Error("Hash() returned nil for solana out")
	}
	if len(h) != 32 {
		t.Errorf("Hash() returned %d bytes, expected 32", len(h))
	}
}

func TestSolanaAddressParse(t *testing.T) {
	// A well-known Solana address (System Program)
	addr := "11111111111111111111111111111111"
	out, err := outscript.ParseSolanaAddress(addr)
	if err != nil {
		t.Fatalf("failed to parse system program address: %s", err)
	}
	roundTrip, err := out.Address("solana")
	if err != nil {
		t.Fatalf("failed to encode address: %s", err)
	}
	if roundTrip != addr {
		t.Errorf("round-trip mismatch: %s != %s", roundTrip, addr)
	}

	// Invalid: too short
	_, err = outscript.ParseSolanaAddress("abc")
	if err == nil {
		t.Error("expected error for short address, got nil")
	}

	// Invalid: not base58
	_, err = outscript.ParseSolanaAddress("0000000000000000000000000000000O") // O is not in base58
	if err == nil {
		t.Error("expected error for invalid base58, got nil")
	}
}

func TestSolanaCompactU16(t *testing.T) {
	// We test compact-u16 indirectly via message serialization round-trips,
	// but let's also build a transaction with specific values to verify encoding.
	feePayer := must(outscript.ParseSolanaKey("11111111111111111111111111111111"))
	blockhash := must(outscript.ParseSolanaKey("11111111111111111111111111111111"))

	tx := outscript.NewSolanaTx(feePayer, blockhash)
	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	var tx2 outscript.SolanaTx
	err = tx2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("unmarshal failed: %s", err)
	}

	if len(tx2.Message.AccountKeys) != len(tx.Message.AccountKeys) {
		t.Errorf("account keys count mismatch: %d != %d", len(tx2.Message.AccountKeys), len(tx.Message.AccountKeys))
	}
}

func TestSolanaTxTransfer(t *testing.T) {
	seed := must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88"))
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	var from outscript.SolanaKey
	copy(from[:], pub)

	to := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	blockhash := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))

	ix := outscript.SolanaTransferInstruction(from, to, 1000000)
	tx := outscript.NewSolanaTx(from, blockhash, ix)

	// Verify structure before signing.
	if tx.Message.Header.NumRequiredSignatures != 1 {
		t.Errorf("expected 1 signer, got %d", tx.Message.Header.NumRequiredSignatures)
	}
	// from (signer+writable), to (writable), system program (readonly) = 3 accounts
	if len(tx.Message.AccountKeys) != 3 {
		t.Errorf("expected 3 account keys, got %d", len(tx.Message.AccountKeys))
	}
	if tx.Message.AccountKeys[0] != from {
		t.Error("fee payer should be first account")
	}

	// Sign
	err := tx.Sign(key)
	if err != nil {
		t.Fatalf("sign failed: %s", err)
	}

	// Hash should be the signature
	h, err := tx.Hash()
	if err != nil {
		t.Fatalf("hash failed: %s", err)
	}
	if len(h) != 64 {
		t.Errorf("expected 64-byte hash, got %d", len(h))
	}
	if !bytes.Equal(h, tx.Signatures[0]) {
		t.Error("hash should equal the first signature")
	}

	// Marshal
	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	// Verify the serialized data is non-trivial
	if len(data) < 100 {
		t.Errorf("serialized tx seems too short: %d bytes", len(data))
	}
}

func TestSolanaTxRoundTrip(t *testing.T) {
	seed := must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88"))
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	var from outscript.SolanaKey
	copy(from[:], pub)

	to := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	blockhash := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))

	ix := outscript.SolanaTransferInstruction(from, to, 500000)
	tx := outscript.NewSolanaTx(from, blockhash, ix)
	err := tx.Sign(key)
	if err != nil {
		t.Fatalf("sign failed: %s", err)
	}

	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal failed: %s", err)
	}

	var tx2 outscript.SolanaTx
	err = tx2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("unmarshal failed: %s", err)
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
	if tx2.Message.Header != tx.Message.Header {
		t.Error("header mismatch")
	}
	if len(tx2.Message.AccountKeys) != len(tx.Message.AccountKeys) {
		t.Fatalf("account keys count mismatch")
	}
	for i := range tx.Message.AccountKeys {
		if tx2.Message.AccountKeys[i] != tx.Message.AccountKeys[i] {
			t.Errorf("account key %d mismatch", i)
		}
	}
	if tx2.Message.RecentBlockhash != tx.Message.RecentBlockhash {
		t.Error("blockhash mismatch")
	}
	if len(tx2.Message.Instructions) != len(tx.Message.Instructions) {
		t.Fatalf("instruction count mismatch")
	}
	for i := range tx.Message.Instructions {
		ix1 := tx.Message.Instructions[i]
		ix2 := tx2.Message.Instructions[i]
		if ix1.ProgramIDIndex != ix2.ProgramIDIndex {
			t.Errorf("instruction %d program index mismatch", i)
		}
		if !bytes.Equal(ix1.AccountIndices, ix2.AccountIndices) {
			t.Errorf("instruction %d account indices mismatch", i)
		}
		if !bytes.Equal(ix1.Data, ix2.Data) {
			t.Errorf("instruction %d data mismatch", i)
		}
	}

	// Re-marshal and verify byte-for-byte equality
	data2, err := tx2.MarshalBinary()
	if err != nil {
		t.Fatalf("re-marshal failed: %s", err)
	}
	if !bytes.Equal(data, data2) {
		t.Error("re-serialized bytes differ from original")
	}
}
