package outscript_test

import (
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestSolanaCreateProgramAddress(t *testing.T) {
	programID := must(outscript.ParseSolanaKey("11111111111111111111111111111111"))

	// With a bump that produces an off-curve result, CreateProgramAddress should succeed.
	// We test indirectly via FindProgramAddress since we don't have a pre-computed vector
	// for CreateProgramAddress alone.
	addr, bump, err := outscript.SolanaFindProgramAddress([][]byte{[]byte("test")}, programID)
	if err != nil {
		t.Fatalf("SolanaFindProgramAddress failed: %s", err)
	}

	// Verify we can reproduce the same address with CreateProgramAddress using the bump.
	addr2, err := outscript.SolanaCreateProgramAddress([][]byte{[]byte("test"), {bump}}, programID)
	if err != nil {
		t.Fatalf("SolanaCreateProgramAddress failed: %s", err)
	}
	if addr != addr2 {
		t.Errorf("addresses don't match: %s != %s", addr, addr2)
	}
}

func TestSolanaFindProgramAddress(t *testing.T) {
	programID := must(outscript.ParseSolanaKey("BPFLoaderUpgradeab1e11111111111111111111111"))

	addr, bump, err := outscript.SolanaFindProgramAddress([][]byte{[]byte("hello")}, programID)
	if err != nil {
		t.Fatalf("SolanaFindProgramAddress failed: %s", err)
	}
	if addr.IsZero() {
		t.Error("expected non-zero address")
	}
	// Bump should be <= 255
	_ = bump

	// The address should be stable (deterministic).
	addr2, bump2, err := outscript.SolanaFindProgramAddress([][]byte{[]byte("hello")}, programID)
	if err != nil {
		t.Fatalf("second call failed: %s", err)
	}
	if addr != addr2 || bump != bump2 {
		t.Error("FindProgramAddress is not deterministic")
	}
}

func TestSolanaPDAValidation(t *testing.T) {
	programID := must(outscript.ParseSolanaKey("11111111111111111111111111111111"))

	// Too many seeds (> 16)
	seeds := make([][]byte, 17)
	for i := range seeds {
		seeds[i] = []byte{byte(i)}
	}
	_, err := outscript.SolanaCreateProgramAddress(seeds, programID)
	if err == nil {
		t.Error("expected error for > 16 seeds")
	}

	// Seed too long (> 32 bytes)
	longSeed := make([]byte, 33)
	_, err = outscript.SolanaCreateProgramAddress([][]byte{longSeed}, programID)
	if err == nil {
		t.Error("expected error for seed > 32 bytes")
	}
}

func TestSolanaPDAMultipleSeeds(t *testing.T) {
	programID := must(outscript.ParseSolanaKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"))

	// Multiple seeds should work
	wallet := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	addr, bump, err := outscript.SolanaFindProgramAddress([][]byte{wallet[:], []byte("seed2")}, programID)
	if err != nil {
		t.Fatalf("SolanaFindProgramAddress with multiple seeds failed: %s", err)
	}

	// Verify round-trip with the bump
	addr2, err := outscript.SolanaCreateProgramAddress([][]byte{wallet[:], []byte("seed2"), {bump}}, programID)
	if err != nil {
		t.Fatalf("SolanaCreateProgramAddress failed: %s", err)
	}
	if addr != addr2 {
		t.Errorf("round-trip failed: %s != %s", addr, addr2)
	}
}
