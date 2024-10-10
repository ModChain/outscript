package outscript

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/typutil"
	"github.com/ModChain/rlp"
	"github.com/ModChain/secp256k1"
	"github.com/ModChain/secp256k1/ecdsa"
	"golang.org/x/crypto/sha3"
)

// LegacyTx
// DynamicFeeTx represents an EIP-1559 transaction
// AccessListTx is the data of EIP-2930 access list transactions
//
// Legacy = rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
// EIP-2930 = 0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, signatureYParity, signatureR, signatureS])
// EIP-1559 = 0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list, signature_y_parity, signature_r, signature_s])
// however, EIP-2930 is so rare we can probably forget about it

type EvmTxType int

const (
	EvmTxLegacy EvmTxType = iota // 0
	EvmTxEIP2930
	EvmTxEIP1559
)

type EvmTx struct {
	Nonce     uint64
	GasTipCap *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap *big.Int // a.k.a. maxFeePerGas, correspond to GasFee if tx type is legacy or eip2930
	Gas       uint64
	To        string
	Value     *big.Int
	Data      []byte
	ChainId   uint64    // in legacy tx, chainId is encoded in v before signature
	Type      EvmTxType // type of transaction: legacy, eip2930 or eip1559
	Signed    bool
	Y, R, S   *big.Int
}

// RlpFields returns the Rlp fields for the given transaction, less the signature fields
func (tx *EvmTx) RlpFields() []any {
	switch tx.Type {
	case EvmTxLegacy:
		return []any{
			tx.Nonce,
			tx.GasFeeCap,
			tx.Gas,
			tx.To,
			tx.Value,
			tx.Data,
		}
	case EvmTxEIP2930:
		return []any{
			tx.ChainId,
			tx.Nonce,
			tx.GasFeeCap,
			tx.Gas,
			tx.To,
			tx.Value,
			tx.Data,
			[]any{},
		}
	case EvmTxEIP1559:
		return []any{
			tx.ChainId,
			tx.Nonce,
			tx.GasTipCap,
			tx.GasFeeCap,
			tx.Gas,
			tx.To,
			tx.Value,
			tx.Data,
			[]any{},
		}
	default:
		return nil
	}
}

// SignBytes returns the bytes used to sign the transaction
func (tx *EvmTx) SignBytes() ([]byte, error) {
	return rlp.EncodeValue(tx.RlpFields())
}

// ParseTransaction will parse an incoming transaction and return an error in case of failure.
// In case of error, the state of tx is undefined.
func (tx *EvmTx) ParseTransaction(buf []byte) error {
	if len(buf) < 1 {
		return io.ErrUnexpectedEOF
	}
	if buf[0] >= 0x80 {
		// legacy transaction as per https://eips.ethereum.org/EIPS/eip-2718
		dec, err := rlp.Decode(buf)
		if err != nil {
			return err
		}
		if len(dec) != 1 {
			return errors.New("invalid rlp data for legacy transaction")
		}
		txData, err := typutil.As[[][]byte](dec[0])
		if err != nil {
			return fmt.Errorf("failed to decode rlp data: %w", err)
		}
		ln := len(txData)
		if ln != 6 && ln != 9 {
			return fmt.Errorf("lgacy transaction must have 6 or 9 fields, got %d", ln)
		}
		tx.Type = EvmTxLegacy
		tx.Nonce = rlp.DecodeUint64(txData[0])
		tx.GasFeeCap = new(big.Int).SetBytes(txData[1])
		tx.Gas = rlp.DecodeUint64(txData[2])
		tx.To = "0x" + hex.EncodeToString(txData[3])
		tx.Value = new(big.Int).SetBytes(txData[4])
		tx.Data = txData[5]
		if ln == 9 {
			// signed
			tx.Signed = true
			tx.Y = new(big.Int).SetBytes(txData[6])
			tx.R = new(big.Int).SetBytes(txData[7])
			tx.S = new(big.Int).SetBytes(txData[8])
		} else {
			tx.Signed = false
		}
		return nil
	}

	return errors.New("not supported")
}

func (tx *EvmTx) Signature() (*ecdsa.Signature, error) {
	if !tx.Signed {
		return nil, errors.New("cannot obtain signature of an unsigned transaction")
	}
	r := new(secp256k1.ModNScalar)
	if !r.SetByteSlice(tx.R.Bytes()) {
		return nil, errors.New("invalid signature (failed to set R)")
	}
	s := new(secp256k1.ModNScalar)
	if !s.SetByteSlice(tx.S.Bytes()) {
		return nil, errors.New("invalid signature (failed to set S)")
	}
	return ecdsa.NewSignature(r, s), nil
}

func (tx *EvmTx) SenderPubkey() (*secp256k1.PublicKey, error) {
	if !tx.Signed {
		return nil, errors.New("cannot obtain signature of an unsigned transaction")
	}
	sig := make([]byte, 65)
	// RecoverCompact expects a signature inform V,R,S
	sig[0] = byte(new(big.Int).And(tx.Y, big.NewInt(1)).Uint64())
	tx.R.FillBytes(sig[1:33])
	tx.S.FillBytes(sig[33:65])

	buf, err := tx.SignBytes()
	if err != nil {
		return nil, err
	}
	pub, comp, err := ecdsa.RecoverCompact(sig, cryptutil.Hash(buf, sha3.NewLegacyKeccak256))
	if err != nil {
		return nil, err
	}
	// TODO use comp
	_ = comp
	return pub, nil
}
