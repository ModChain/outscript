package outscript

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"

	"github.com/ModChain/base58"
)

// SolanaKey is a 32-byte public key used to identify accounts on the Solana network.
type SolanaKey [32]byte

// SolanaSystemProgram is the address of the Solana System Program.
var SolanaSystemProgram = mustParseSolanaKey("11111111111111111111111111111111")

func mustParseSolanaKey(s string) SolanaKey {
	k, err := ParseSolanaKey(s)
	if err != nil {
		panic(err)
	}
	return k
}

// ParseSolanaKey parses a base58-encoded string into a SolanaKey.
func ParseSolanaKey(s string) (SolanaKey, error) {
	buf, err := base58.Bitcoin.Decode(s)
	if err != nil {
		return SolanaKey{}, fmt.Errorf("failed to decode solana key: %w", err)
	}
	if len(buf) != 32 {
		return SolanaKey{}, fmt.Errorf("invalid solana key: expected 32 bytes, got %d", len(buf))
	}
	var k SolanaKey
	copy(k[:], buf)
	return k, nil
}

// String returns the base58 encoding of the key.
func (k SolanaKey) String() string {
	return base58.Bitcoin.Encode(k[:])
}

// IsZero reports whether the key is all zeros.
func (k SolanaKey) IsZero() bool {
	return k == SolanaKey{}
}

// SolanaAccountMeta describes an account referenced by an instruction.
type SolanaAccountMeta struct {
	Pubkey     SolanaKey
	IsSigner   bool
	IsWritable bool
}

// SolanaInstruction is a high-level instruction before account compilation.
type SolanaInstruction struct {
	ProgramID SolanaKey
	Accounts  []SolanaAccountMeta
	Data      []byte
}

// SolanaTransferInstruction returns a System Program transfer instruction
// that moves lamports from one account to another.
func SolanaTransferInstruction(from, to SolanaKey, lamports uint64) SolanaInstruction {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], 2) // Transfer instruction index
	binary.LittleEndian.PutUint64(data[4:12], lamports)
	return SolanaInstruction{
		ProgramID: SolanaSystemProgram,
		Accounts: []SolanaAccountMeta{
			{Pubkey: from, IsSigner: true, IsWritable: true},
			{Pubkey: to, IsSigner: false, IsWritable: true},
		},
		Data: data,
	}
}

// SolanaMessageHeader contains the counts needed to distinguish signer and
// readonly accounts in a transaction message.
type SolanaMessageHeader struct {
	NumRequiredSignatures       uint8
	NumReadonlySignedAccounts   uint8
	NumReadonlyUnsignedAccounts uint8
}

// SolanaCompiledInstruction is an instruction with account references replaced
// by indices into the message's account key array.
type SolanaCompiledInstruction struct {
	ProgramIDIndex uint8
	AccountIndices []uint8
	Data           []byte
}

// SolanaMessage is the message portion of a Solana transaction.
type SolanaMessage struct {
	Header          SolanaMessageHeader
	AccountKeys     []SolanaKey
	RecentBlockhash SolanaKey
	Instructions    []SolanaCompiledInstruction
}

// SolanaTx represents a Solana legacy (unversioned) transaction.
type SolanaTx struct {
	Signatures [][]byte
	Message    SolanaMessage
}

// solanaAccountInfo tracks the merged permissions for a single account during compilation.
type solanaAccountInfo struct {
	key        SolanaKey
	isSigner   bool
	isWritable bool
}

// NewSolanaTx compiles a set of high-level instructions into a transaction.
// The fee payer is always placed first in the account list as a writable signer.
func NewSolanaTx(feePayer, recentBlockhash SolanaKey, instructions ...SolanaInstruction) *SolanaTx {
	// Collect and deduplicate accounts, merging permissions.
	seen := make(map[SolanaKey]*solanaAccountInfo)

	// Fee payer is always signer + writable.
	seen[feePayer] = &solanaAccountInfo{key: feePayer, isSigner: true, isWritable: true}

	for _, ix := range instructions {
		for _, acc := range ix.Accounts {
			if info, ok := seen[acc.Pubkey]; ok {
				info.isSigner = info.isSigner || acc.IsSigner
				info.isWritable = info.isWritable || acc.IsWritable
			} else {
				seen[acc.Pubkey] = &solanaAccountInfo{
					key:        acc.Pubkey,
					isSigner:   acc.IsSigner,
					isWritable: acc.IsWritable,
				}
			}
		}
		// Program IDs are added as non-signer, readonly (unless already present with higher perms).
		if _, ok := seen[ix.ProgramID]; !ok {
			seen[ix.ProgramID] = &solanaAccountInfo{
				key:        ix.ProgramID,
				isSigner:   false,
				isWritable: false,
			}
		}
	}

	// Sort accounts into 4 groups:
	// 1. signer + writable
	// 2. signer + readonly
	// 3. non-signer + writable
	// 4. non-signer + readonly
	// Within each group, maintain stable order (fee payer always first overall).
	var signerWritable, signerReadonly, nonsignerWritable, nonsignerReadonly []solanaAccountInfo
	for _, info := range seen {
		if info.key == feePayer {
			continue // handled separately
		}
		switch {
		case info.isSigner && info.isWritable:
			signerWritable = append(signerWritable, *info)
		case info.isSigner && !info.isWritable:
			signerReadonly = append(signerReadonly, *info)
		case !info.isSigner && info.isWritable:
			nonsignerWritable = append(nonsignerWritable, *info)
		default:
			nonsignerReadonly = append(nonsignerReadonly, *info)
		}
	}

	// Stable sort each group by key bytes for deterministic ordering.
	sortByKey := func(s []solanaAccountInfo) {
		sort.SliceStable(s, func(i, j int) bool {
			return slices.Compare(s[i].key[:], s[j].key[:]) < 0
		})
	}
	sortByKey(signerWritable)
	sortByKey(signerReadonly)
	sortByKey(nonsignerWritable)
	sortByKey(nonsignerReadonly)

	// Build the final account list.
	feePayerInfo := *seen[feePayer]
	allAccounts := make([]solanaAccountInfo, 0, len(seen))
	allAccounts = append(allAccounts, feePayerInfo)
	allAccounts = append(allAccounts, signerWritable...)
	allAccounts = append(allAccounts, signerReadonly...)
	allAccounts = append(allAccounts, nonsignerWritable...)
	allAccounts = append(allAccounts, nonsignerReadonly...)

	// Build index map.
	indexMap := make(map[SolanaKey]uint8, len(allAccounts))
	accountKeys := make([]SolanaKey, len(allAccounts))
	for i, acc := range allAccounts {
		indexMap[acc.key] = uint8(i)
		accountKeys[i] = acc.key
	}

	// Compute header counts.
	numSigners := 1 + len(signerWritable) + len(signerReadonly) // +1 for fee payer
	numReadonlySigned := len(signerReadonly)
	numReadonlyUnsigned := len(nonsignerReadonly)

	// Compile instructions.
	compiled := make([]SolanaCompiledInstruction, len(instructions))
	for i, ix := range instructions {
		indices := make([]uint8, len(ix.Accounts))
		for j, acc := range ix.Accounts {
			indices[j] = indexMap[acc.Pubkey]
		}
		compiled[i] = SolanaCompiledInstruction{
			ProgramIDIndex: indexMap[ix.ProgramID],
			AccountIndices: indices,
			Data:           ix.Data,
		}
	}

	msg := SolanaMessage{
		Header: SolanaMessageHeader{
			NumRequiredSignatures:       uint8(numSigners),
			NumReadonlySignedAccounts:   uint8(numReadonlySigned),
			NumReadonlyUnsignedAccounts: uint8(numReadonlyUnsigned),
		},
		AccountKeys:     accountKeys,
		RecentBlockhash: recentBlockhash,
		Instructions:    compiled,
	}

	return &SolanaTx{
		Signatures: make([][]byte, numSigners),
		Message:    msg,
	}
}

// Sign signs the transaction message with the provided Ed25519 private keys.
// Keys are matched to signature slots by their public key.
func (tx *SolanaTx) Sign(keys ...ed25519.PrivateKey) error {
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return err
	}

	numSigners := int(tx.Message.Header.NumRequiredSignatures)
	for _, key := range keys {
		pub := key.Public().(ed25519.PublicKey)
		var pubKey SolanaKey
		copy(pubKey[:], pub)

		idx := -1
		for i := 0; i < numSigners; i++ {
			if tx.Message.AccountKeys[i] == pubKey {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("key %s is not a required signer", pubKey)
		}
		sig := ed25519.Sign(key, msgBytes)
		tx.Signatures[idx] = sig
	}
	return nil
}

// Hash returns the transaction ID, which is the first signature (64 bytes).
func (tx *SolanaTx) Hash() ([]byte, error) {
	if len(tx.Signatures) == 0 || len(tx.Signatures[0]) == 0 {
		return nil, errors.New("transaction has no signature")
	}
	return slices.Clone(tx.Signatures[0]), nil
}

// MarshalBinary serializes the transaction into the Solana wire format.
func (tx *SolanaTx) MarshalBinary() ([]byte, error) {
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, err
	}

	buf := solanaEncodeCompactU16(len(tx.Signatures))
	for _, sig := range tx.Signatures {
		if len(sig) == 0 {
			buf = append(buf, make([]byte, 64)...)
		} else {
			if len(sig) != 64 {
				return nil, fmt.Errorf("invalid signature length: %d", len(sig))
			}
			buf = append(buf, sig...)
		}
	}
	buf = append(buf, msgBytes...)
	return buf, nil
}

// UnmarshalBinary deserializes a transaction from the Solana wire format.
func (tx *SolanaTx) UnmarshalBinary(data []byte) error {
	r := data

	sigCount, n, err := solanaDecodeCompactU16(r)
	if err != nil {
		return fmt.Errorf("reading signature count: %w", err)
	}
	r = r[n:]

	tx.Signatures = make([][]byte, sigCount)
	for i := 0; i < sigCount; i++ {
		if len(r) < 64 {
			return io.ErrUnexpectedEOF
		}
		tx.Signatures[i] = slices.Clone(r[:64])
		r = r[64:]
	}

	return tx.Message.UnmarshalBinary(r)
}

// MarshalBinary serializes the message into the Solana wire format.
func (msg *SolanaMessage) MarshalBinary() ([]byte, error) {
	buf := []byte{
		msg.Header.NumRequiredSignatures,
		msg.Header.NumReadonlySignedAccounts,
		msg.Header.NumReadonlyUnsignedAccounts,
	}

	buf = append(buf, solanaEncodeCompactU16(len(msg.AccountKeys))...)
	for _, key := range msg.AccountKeys {
		buf = append(buf, key[:]...)
	}

	buf = append(buf, msg.RecentBlockhash[:]...)

	buf = append(buf, solanaEncodeCompactU16(len(msg.Instructions))...)
	for _, ix := range msg.Instructions {
		buf = append(buf, ix.ProgramIDIndex)
		buf = append(buf, solanaEncodeCompactU16(len(ix.AccountIndices))...)
		buf = append(buf, ix.AccountIndices...)
		buf = append(buf, solanaEncodeCompactU16(len(ix.Data))...)
		buf = append(buf, ix.Data...)
	}

	return buf, nil
}

// UnmarshalBinary deserializes a message from the Solana wire format.
func (msg *SolanaMessage) UnmarshalBinary(data []byte) error {
	r := data

	if len(r) < 3 {
		return io.ErrUnexpectedEOF
	}
	msg.Header.NumRequiredSignatures = r[0]
	msg.Header.NumReadonlySignedAccounts = r[1]
	msg.Header.NumReadonlyUnsignedAccounts = r[2]
	r = r[3:]

	keyCount, n, err := solanaDecodeCompactU16(r)
	if err != nil {
		return fmt.Errorf("reading account key count: %w", err)
	}
	r = r[n:]

	msg.AccountKeys = make([]SolanaKey, keyCount)
	for i := 0; i < keyCount; i++ {
		if len(r) < 32 {
			return io.ErrUnexpectedEOF
		}
		copy(msg.AccountKeys[i][:], r[:32])
		r = r[32:]
	}

	if len(r) < 32 {
		return io.ErrUnexpectedEOF
	}
	copy(msg.RecentBlockhash[:], r[:32])
	r = r[32:]

	ixCount, n, err := solanaDecodeCompactU16(r)
	if err != nil {
		return fmt.Errorf("reading instruction count: %w", err)
	}
	r = r[n:]

	msg.Instructions = make([]SolanaCompiledInstruction, ixCount)
	for i := 0; i < ixCount; i++ {
		if len(r) < 1 {
			return io.ErrUnexpectedEOF
		}
		msg.Instructions[i].ProgramIDIndex = r[0]
		r = r[1:]

		accCount, n, err := solanaDecodeCompactU16(r)
		if err != nil {
			return fmt.Errorf("reading account index count: %w", err)
		}
		r = r[n:]
		if len(r) < accCount {
			return io.ErrUnexpectedEOF
		}
		msg.Instructions[i].AccountIndices = slices.Clone(r[:accCount])
		r = r[accCount:]

		dataLen, n, err := solanaDecodeCompactU16(r)
		if err != nil {
			return fmt.Errorf("reading instruction data length: %w", err)
		}
		r = r[n:]
		if len(r) < dataLen {
			return io.ErrUnexpectedEOF
		}
		msg.Instructions[i].Data = slices.Clone(r[:dataLen])
		r = r[dataLen:]
	}

	return nil
}

// solanaEncodeCompactU16 encodes an integer as Solana's compact-u16 format.
// Values 0-0x7f use 1 byte, 0x80-0x3fff use 2 bytes, 0x4000-0xffff use 3 bytes.
func solanaEncodeCompactU16(v int) []byte {
	if v < 0 || v > 0xffff {
		panic("compact-u16 value out of range")
	}
	if v < 0x80 {
		return []byte{byte(v)}
	}
	if v < 0x4000 {
		return []byte{byte(v&0x7f) | 0x80, byte(v >> 7)}
	}
	return []byte{byte(v&0x7f) | 0x80, byte((v>>7)&0x7f) | 0x80, byte(v >> 14)}
}

// solanaDecodeCompactU16 decodes a compact-u16 value and returns the value,
// number of bytes consumed, and any error.
func solanaDecodeCompactU16(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	b0 := data[0]
	if b0 < 0x80 {
		return int(b0), 1, nil
	}
	if len(data) < 2 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	b1 := data[1]
	if b1 < 0x80 {
		return int(b0&0x7f) | int(b1)<<7, 2, nil
	}
	if len(data) < 3 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	b2 := data[2]
	if b2 > 3 {
		return 0, 0, errors.New("compact-u16 overflow")
	}
	return int(b0&0x7f) | int(b1&0x7f)<<7 | int(b2)<<14, 3, nil
}
