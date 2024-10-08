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
// EIP-4844 = 0x03 || [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes, y_parity, r, s]
// however, EIP-2930 is so rare we can probably forget about it

type EvmTxType int

const (
	EvmTxLegacy EvmTxType = iota
	EvmTxEIP2930
	EvmTxEIP1559
	EvmTxEIP4844 //
)

type EvmTx struct {
	Nonce      uint64
	GasTipCap  *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap  *big.Int // a.k.a. maxFeePerGas, correspond to GasFee if tx type is legacy or eip2930
	Gas        uint64 // gas of tx, can be obtained with eth_estimateGas, 21000 if Data is empty
	To         string
	Value      *big.Int
	Data       []byte
	ChainId    uint64    // in legacy tx, chainId is encoded in v before signature
	Type       EvmTxType // type of transaction: legacy, eip2930 or eip1559
	AccessList []any     // TODO
	Signed     bool
	Y, R, S    *big.Int
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

func (tx *EvmTx) typeValue() byte {
	switch tx.Type {
	case EvmTxLegacy:
		return 0
	case EvmTxEIP2930:
		return 1
	case EvmTxEIP1559:
		return 2
	case EvmTxEIP4844:
		return 3
	default:
		return 0xff // :(
	}
}

// SignBytes returns the bytes used to sign the transaction
func (tx *EvmTx) SignBytes() ([]byte, error) {
	switch tx.Type {
	case EvmTxLegacy:
		f := tx.RlpFields()
		if tx.ChainId != 0 {
			// if ChainId == 0, we assume no EIP-155
			f = append(f, tx.ChainId, 0, 0)
		}
		return rlp.EncodeValue(f)
	default:
		buf, err := rlp.EncodeValue(tx.RlpFields())
		if err != nil {
			return nil, err
		}
		return append([]byte{tx.typeValue()}, buf...), nil
	}
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
			tx.Y = new(big.Int).SetBytes(txData[6]) // 27|28, or ChainId * 2 + 35 + (v & 1) if EIP-155
			tx.R = new(big.Int).SetBytes(txData[7])
			tx.S = new(big.Int).SetBytes(txData[8])
		} else {
			tx.Signed = false
		}
		return nil
	}
	switch buf[0] {
	case 1: // EvmTxEIP2930
		dec, err := rlp.Decode(buf[1:])
		if err != nil {
			return err
		}
		if len(dec) != 1 {
			return errors.New("invalid rlp data for legacy transaction")
		}
		txData := dec[0].([]any)
		ln := len(txData)
		if ln != 8 && ln != 11 {
			return fmt.Errorf("EIP-2930 transaction must have 8 or 11 fields, got %d", ln)
		}
		tx.Type = EvmTxEIP2930
		tx.ChainId = rlp.DecodeUint64(txData[0].([]byte))
		tx.Nonce = rlp.DecodeUint64(txData[1].([]byte))
		tx.GasFeeCap = new(big.Int).SetBytes(txData[2].([]byte))
		tx.Gas = rlp.DecodeUint64(txData[3].([]byte))
		tx.To = "0x" + hex.EncodeToString(txData[4].([]byte))
		tx.Value = new(big.Int).SetBytes(txData[5].([]byte))
		tx.Data = txData[6].([]byte)
		tx.AccessList = txData[7].([]any) // TODO
		if ln == 11 {
			tx.Signed = true
			tx.Y = new(big.Int).SetBytes(txData[8].([]byte))
			tx.R = new(big.Int).SetBytes(txData[9].([]byte))
			tx.S = new(big.Int).SetBytes(txData[10].([]byte))
		} else {
			tx.Signed = false
		}
		return nil
	case 2: // EvmTxEIP1559
		dec, err := rlp.Decode(buf[1:])
		if err != nil {
			return err
		}
		if len(dec) != 1 {
			return errors.New("invalid rlp data for legacy transaction")
		}
		txData := dec[0].([]any)
		ln := len(txData)
		if ln != 9 && ln != 12 {
			return fmt.Errorf("EIP-1559 transaction must have 9 or 12 fields, got %d", ln)
		}
		tx.Type = EvmTxEIP1559
		tx.ChainId = rlp.DecodeUint64(txData[0].([]byte))
		tx.Nonce = rlp.DecodeUint64(txData[1].([]byte))
		tx.GasTipCap = new(big.Int).SetBytes(txData[2].([]byte))
		tx.GasFeeCap = new(big.Int).SetBytes(txData[3].([]byte))
		tx.Gas = rlp.DecodeUint64(txData[4].([]byte))
		tx.To = "0x" + hex.EncodeToString(txData[5].([]byte))
		tx.Value = new(big.Int).SetBytes(txData[6].([]byte))
		tx.Data = txData[7].([]byte)
		tx.AccessList = txData[8].([]any) // TODO
		if ln == 12 {
			tx.Signed = true
			tx.Y = new(big.Int).SetBytes(txData[9].([]byte))
			tx.R = new(big.Int).SetBytes(txData[10].([]byte))
			tx.S = new(big.Int).SetBytes(txData[11].([]byte))
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
	v := tx.Y.Uint64()
	if tx.Type == EvmTxLegacy {
		if v >= 35 {
			// EIP-155: v = ChainId * 2 + 35 + (v & 1)
			bit := 1 - (v & 1)
			v -= 35 + bit
			tx.ChainId = v / 2
			v = 27 + bit
		} else {
			tx.ChainId = 0
		}
	} else {
		v = 27 + v
	}
	sig[0] = byte(v)
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
	if comp {
		// ethereum expects uncompressed
		return nil, errors.New("invalid compressed flag, expected compressed=false")
	}
	return pub, nil
}

func (tx *EvmTx) SenderAddress() (string, error) {
	pubkey, err := tx.SenderPubkey()
	if err != nil {
		return "", err
	}
	addr := New(pubkey).Generate("eth")
	return eip55(addr), nil
}
