package outscript

import (
	"encoding/binary"
	"fmt"
)

// Well-known Solana program addresses.
var (
	SolanaComputeBudgetProgram    = mustParseSolanaKey("ComputeBudget111111111111111111111111111111")
	SolanaTokenProgram            = mustParseSolanaKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	SolanaATAProgram              = mustParseSolanaKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
	SolanaRecentBlockhashesSysvar = mustParseSolanaKey("SysvarRecentB1ockHashes11111111111111111111")
)

// SolanaSetComputeUnitLimit returns a Compute Budget instruction that sets
// the maximum number of compute units the transaction may consume.
func SolanaSetComputeUnitLimit(units uint32) SolanaInstruction {
	data := make([]byte, 5)
	data[0] = 2 // SetComputeUnitLimit instruction index
	binary.LittleEndian.PutUint32(data[1:5], units)
	return SolanaInstruction{
		ProgramID: SolanaComputeBudgetProgram,
		Data:      data,
	}
}

// SolanaSetComputeUnitPrice returns a Compute Budget instruction that sets
// the compute unit price in micro-lamports for priority fee calculation.
func SolanaSetComputeUnitPrice(microLamports uint64) SolanaInstruction {
	data := make([]byte, 9)
	data[0] = 3 // SetComputeUnitPrice instruction index
	binary.LittleEndian.PutUint64(data[1:9], microLamports)
	return SolanaInstruction{
		ProgramID: SolanaComputeBudgetProgram,
		Data:      data,
	}
}

// SolanaSPLTransferInstruction returns an SPL Token Program transfer instruction
// that moves tokens between token accounts.
func SolanaSPLTransferInstruction(source, destination, owner SolanaKey, amount uint64) SolanaInstruction {
	data := make([]byte, 9)
	data[0] = 3 // Transfer instruction index
	binary.LittleEndian.PutUint64(data[1:9], amount)
	return SolanaInstruction{
		ProgramID: SolanaTokenProgram,
		Accounts: []SolanaAccountMeta{
			{Pubkey: source, IsSigner: false, IsWritable: true},
			{Pubkey: destination, IsSigner: false, IsWritable: true},
			{Pubkey: owner, IsSigner: true, IsWritable: false},
		},
		Data: data,
	}
}

// SolanaGetAssociatedTokenAddress derives the Associated Token Account address
// for the given wallet and token mint.
func SolanaGetAssociatedTokenAddress(wallet, mint SolanaKey) (SolanaKey, error) {
	addr, _, err := SolanaFindProgramAddress(
		[][]byte{wallet[:], SolanaTokenProgram[:], mint[:]},
		SolanaATAProgram,
	)
	return addr, err
}

// SolanaCreateATAInstruction returns an instruction to create an Associated Token Account
// for the given wallet and token mint. The payer funds the account creation.
func SolanaCreateATAInstruction(payer, wallet, mint SolanaKey) (SolanaInstruction, error) {
	ata, err := SolanaGetAssociatedTokenAddress(wallet, mint)
	if err != nil {
		return SolanaInstruction{}, fmt.Errorf("failed to derive ATA: %w", err)
	}
	return SolanaInstruction{
		ProgramID: SolanaATAProgram,
		Accounts: []SolanaAccountMeta{
			{Pubkey: payer, IsSigner: true, IsWritable: true},
			{Pubkey: ata, IsSigner: false, IsWritable: true},
			{Pubkey: wallet, IsSigner: false, IsWritable: false},
			{Pubkey: mint, IsSigner: false, IsWritable: false},
			{Pubkey: SolanaSystemProgram, IsSigner: false, IsWritable: false},
			{Pubkey: SolanaTokenProgram, IsSigner: false, IsWritable: false},
		},
	}, nil
}

// SolanaAdvanceNonceInstruction returns a System Program instruction to advance
// a durable nonce account. This instruction must be placed first in the transaction.
func SolanaAdvanceNonceInstruction(nonceAccount, nonceAuthority SolanaKey) SolanaInstruction {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], 4) // AdvanceNonceAccount instruction index
	return SolanaInstruction{
		ProgramID: SolanaSystemProgram,
		Accounts: []SolanaAccountMeta{
			{Pubkey: nonceAccount, IsSigner: false, IsWritable: true},
			{Pubkey: SolanaRecentBlockhashesSysvar, IsSigner: false, IsWritable: false},
			{Pubkey: nonceAuthority, IsSigner: true, IsWritable: false},
		},
		Data: data,
	}
}
