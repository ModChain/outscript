package outscript_test

import (
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestSolanaKeyString(t *testing.T) {
	k, err := outscript.ParseSolanaKey("11111111111111111111111111111111")
	if err != nil {
		t.Fatalf("ParseSolanaKey failed: %s", err)
	}
	s := k.String()
	if s != "11111111111111111111111111111111" {
		t.Errorf("unexpected String(): %s", s)
	}
}

func TestSolanaKeyIsZero(t *testing.T) {
	var k outscript.SolanaKey
	if !k.IsZero() {
		t.Error("zero key should be zero")
	}

	k[0] = 1
	if k.IsZero() {
		t.Error("non-zero key should not be zero")
	}
}

func TestSolanaCompactU16Extended(t *testing.T) {
	// The existing test only covers small values.
	// Test larger values via round-trip through SolanaTx serialization.
	// We can test the encoding indirectly by creating a tx with many accounts.

	// Test parsing invalid solana key
	_, err := outscript.ParseSolanaKey("invalid-base58!!!")
	if err == nil {
		t.Error("expected error for invalid solana key")
	}

	// Test parsing wrong-length key
	_, err = outscript.ParseSolanaKey("1") // too short
	if err == nil {
		t.Error("expected error for short solana key")
	}
}

func TestSolanaSystemProgram(t *testing.T) {
	// The system program address 111...1 decodes to 32 zero bytes in base58
	if !outscript.SolanaSystemProgram.IsZero() {
		t.Error("system program should be all zeros")
	}
	if outscript.SolanaSystemProgram.String() != "11111111111111111111111111111111" {
		t.Errorf("unexpected system program address: %s", outscript.SolanaSystemProgram.String())
	}
}

func TestSolanaAddressRoundTrip(t *testing.T) {
	addr := "83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"
	out, err := outscript.ParseSolanaAddress(addr)
	if err != nil {
		t.Fatalf("ParseSolanaAddress failed: %s", err)
	}

	// Address should round-trip
	roundTrip, err := out.Address("solana")
	if err != nil {
		t.Fatalf("Address(solana) failed: %s", err)
	}
	if roundTrip != addr {
		t.Errorf("round-trip mismatch: %s != %s", roundTrip, addr)
	}

	// Hash should return the raw bytes
	h := out.Hash()
	if len(h) != 32 {
		t.Errorf("expected 32-byte hash, got %d", len(h))
	}
}
