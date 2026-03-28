package outscript_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestSolanaComputeBudgetProgram(t *testing.T) {
	// Verify the program address is not zero
	if outscript.SolanaComputeBudgetProgram.IsZero() {
		t.Error("ComputeBudget program address should not be zero")
	}
}

func TestSolanaSetComputeUnitLimit(t *testing.T) {
	ix := outscript.SolanaSetComputeUnitLimit(200000)

	if ix.ProgramID != outscript.SolanaComputeBudgetProgram {
		t.Error("wrong program ID")
	}
	if len(ix.Accounts) != 0 {
		t.Errorf("expected 0 accounts, got %d", len(ix.Accounts))
	}
	if len(ix.Data) != 5 {
		t.Fatalf("expected 5 bytes data, got %d", len(ix.Data))
	}
	if ix.Data[0] != 2 {
		t.Errorf("expected instruction index 2, got %d", ix.Data[0])
	}
	units := binary.LittleEndian.Uint32(ix.Data[1:5])
	if units != 200000 {
		t.Errorf("expected 200000 units, got %d", units)
	}
}

func TestSolanaSetComputeUnitPrice(t *testing.T) {
	ix := outscript.SolanaSetComputeUnitPrice(50000)

	if ix.ProgramID != outscript.SolanaComputeBudgetProgram {
		t.Error("wrong program ID")
	}
	if len(ix.Accounts) != 0 {
		t.Errorf("expected 0 accounts, got %d", len(ix.Accounts))
	}
	if len(ix.Data) != 9 {
		t.Fatalf("expected 9 bytes data, got %d", len(ix.Data))
	}
	if ix.Data[0] != 3 {
		t.Errorf("expected instruction index 3, got %d", ix.Data[0])
	}
	price := binary.LittleEndian.Uint64(ix.Data[1:9])
	if price != 50000 {
		t.Errorf("expected 50000 micro-lamports, got %d", price)
	}
}

func TestSolanaSPLTransfer(t *testing.T) {
	source := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	dest := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))
	owner := must(outscript.ParseSolanaKey("11111111111111111111111111111111"))

	ix := outscript.SolanaSPLTransferInstruction(source, dest, owner, 1000000)

	if ix.ProgramID != outscript.SolanaTokenProgram {
		t.Error("wrong program ID")
	}
	if len(ix.Accounts) != 3 {
		t.Fatalf("expected 3 accounts, got %d", len(ix.Accounts))
	}
	// source: writable, not signer
	if ix.Accounts[0].Pubkey != source || ix.Accounts[0].IsSigner || !ix.Accounts[0].IsWritable {
		t.Error("source account flags incorrect")
	}
	// destination: writable, not signer
	if ix.Accounts[1].Pubkey != dest || ix.Accounts[1].IsSigner || !ix.Accounts[1].IsWritable {
		t.Error("destination account flags incorrect")
	}
	// owner: signer, not writable
	if ix.Accounts[2].Pubkey != owner || !ix.Accounts[2].IsSigner || ix.Accounts[2].IsWritable {
		t.Error("owner account flags incorrect")
	}

	if len(ix.Data) != 9 {
		t.Fatalf("expected 9 bytes data, got %d", len(ix.Data))
	}
	if ix.Data[0] != 3 {
		t.Errorf("expected instruction index 3, got %d", ix.Data[0])
	}
	amount := binary.LittleEndian.Uint64(ix.Data[1:9])
	if amount != 1000000 {
		t.Errorf("expected 1000000, got %d", amount)
	}
}

func TestSolanaGetAssociatedTokenAddress(t *testing.T) {
	wallet := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	mint := must(outscript.ParseSolanaKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")) // USDC mint

	ata, err := outscript.SolanaGetAssociatedTokenAddress(wallet, mint)
	if err != nil {
		t.Fatalf("SolanaGetAssociatedTokenAddress failed: %s", err)
	}
	if ata.IsZero() {
		t.Error("ATA should not be zero")
	}

	// Derivation should be deterministic
	ata2, err := outscript.SolanaGetAssociatedTokenAddress(wallet, mint)
	if err != nil {
		t.Fatalf("second derivation failed: %s", err)
	}
	if ata != ata2 {
		t.Error("ATA derivation is not deterministic")
	}
}

func TestSolanaCreateATAInstruction(t *testing.T) {
	payer := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	wallet := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))
	mint := must(outscript.ParseSolanaKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"))

	ix, err := outscript.SolanaCreateATAInstruction(payer, wallet, mint)
	if err != nil {
		t.Fatalf("SolanaCreateATAInstruction failed: %s", err)
	}

	if ix.ProgramID != outscript.SolanaATAProgram {
		t.Error("wrong program ID")
	}
	if len(ix.Accounts) != 6 {
		t.Fatalf("expected 6 accounts, got %d", len(ix.Accounts))
	}

	// Verify account ordering: payer, ata, wallet, mint, system, token
	if ix.Accounts[0].Pubkey != payer || !ix.Accounts[0].IsSigner || !ix.Accounts[0].IsWritable {
		t.Error("payer account flags incorrect")
	}
	if !ix.Accounts[1].IsWritable || ix.Accounts[1].IsSigner {
		t.Error("ATA account flags incorrect")
	}
	if ix.Accounts[2].Pubkey != wallet {
		t.Error("wallet should be third account")
	}
	if ix.Accounts[3].Pubkey != mint {
		t.Error("mint should be fourth account")
	}
	if ix.Accounts[4].Pubkey != outscript.SolanaSystemProgram {
		t.Error("system program should be fifth account")
	}
	if ix.Accounts[5].Pubkey != outscript.SolanaTokenProgram {
		t.Error("token program should be sixth account")
	}

	// ATA address should match derivation
	expectedATA, err := outscript.SolanaGetAssociatedTokenAddress(wallet, mint)
	if err != nil {
		t.Fatalf("derivation failed: %s", err)
	}
	if ix.Accounts[1].Pubkey != expectedATA {
		t.Error("ATA address mismatch")
	}
}

func TestSolanaAdvanceNonce(t *testing.T) {
	nonceAccount := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	authority := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))

	ix := outscript.SolanaAdvanceNonceInstruction(nonceAccount, authority)

	if ix.ProgramID != outscript.SolanaSystemProgram {
		t.Error("wrong program ID")
	}
	if len(ix.Accounts) != 3 {
		t.Fatalf("expected 3 accounts, got %d", len(ix.Accounts))
	}
	// nonce account: writable
	if ix.Accounts[0].Pubkey != nonceAccount || !ix.Accounts[0].IsWritable {
		t.Error("nonce account flags incorrect")
	}
	// recent blockhashes sysvar
	if ix.Accounts[1].Pubkey != outscript.SolanaRecentBlockhashesSysvar {
		t.Error("second account should be RecentBlockhashes sysvar")
	}
	// authority: signer
	if ix.Accounts[2].Pubkey != authority || !ix.Accounts[2].IsSigner {
		t.Error("authority account flags incorrect")
	}

	if len(ix.Data) != 4 {
		t.Fatalf("expected 4 bytes data, got %d", len(ix.Data))
	}
	index := binary.LittleEndian.Uint32(ix.Data[0:4])
	if index != 4 {
		t.Errorf("expected instruction index 4, got %d", index)
	}
}

func TestSolanaComputeBudgetTxRoundTrip(t *testing.T) {
	seed := must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88"))
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	var from outscript.SolanaKey
	copy(from[:], pub)

	to := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	blockhash := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))

	// Build transaction with priority fee + transfer
	ixLimit := outscript.SolanaSetComputeUnitLimit(200000)
	ixPrice := outscript.SolanaSetComputeUnitPrice(50000)
	ixTransfer := outscript.SolanaTransferInstruction(from, to, 1000000)

	tx, err := outscript.NewSolanaTx(from, blockhash, ixLimit, ixPrice, ixTransfer)
	if err != nil {
		t.Fatalf("NewSolanaTx failed: %s", err)
	}

	err = tx.Sign(key)
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

	// Verify round-trip
	data2, err := tx2.MarshalBinary()
	if err != nil {
		t.Fatalf("re-marshal failed: %s", err)
	}
	if !bytes.Equal(data, data2) {
		t.Error("round-trip bytes differ")
	}

	// Should have 3 instructions
	if len(tx2.Message.Instructions) != 3 {
		t.Errorf("expected 3 instructions, got %d", len(tx2.Message.Instructions))
	}
}

func TestSolanaNonceTxRoundTrip(t *testing.T) {
	seed := must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88"))
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	var from outscript.SolanaKey
	copy(from[:], pub)

	to := must(outscript.ParseSolanaKey("83astBRguLMdt2h5U1Tpdq5tjFoJ6noeGwaY3mDLVcri"))
	nonceAccount := must(outscript.ParseSolanaKey("EETubP5AKHgjPAhzPkA6E6HPBj7HtchdMWv2SzTqiYsC"))
	blockhash := must(outscript.ParseSolanaKey("11111111111111111111111111111111"))

	// Nonce advance must be first instruction
	ixNonce := outscript.SolanaAdvanceNonceInstruction(nonceAccount, from)
	ixTransfer := outscript.SolanaTransferInstruction(from, to, 1000000)

	tx, err := outscript.NewSolanaTx(from, blockhash, ixNonce, ixTransfer)
	if err != nil {
		t.Fatalf("NewSolanaTx failed: %s", err)
	}

	err = tx.Sign(key)
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

	data2, err := tx2.MarshalBinary()
	if err != nil {
		t.Fatalf("re-marshal failed: %s", err)
	}
	if !bytes.Equal(data, data2) {
		t.Error("round-trip bytes differ")
	}

	// Should have 2 instructions
	if len(tx2.Message.Instructions) != 2 {
		t.Errorf("expected 2 instructions, got %d", len(tx2.Message.Instructions))
	}
}
