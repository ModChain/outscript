package outscript

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/typutil"
	"github.com/ModChain/rlp"
	"github.com/ModChain/secp256k1"
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
	Gas        uint64   // gas of tx, can be obtained with eth_estimateGas, 21000 if Data is empty
	To         string
	Value      *big.Int
	Data       []byte
	ChainId    uint64    // in legacy tx, chainId is encoded in v before signature
	Type       EvmTxType // type of transaction: legacy, eip2930 or eip1559
	AccessList []any     // TODO
	Signed     bool
	Y, R, S    *big.Int
}

// evmTxJson is used when encoding/decoding evmTx into json
type evmTxJson struct {
	From     string `json:"from,omitempty"` // not used when reading but useful for debug
	Gas      string `json:"gas"`
	GasPrice string `json:"gasPrice"`
	Hash     string `json:"hash,omitempty"`
	Input    string `json:"input"`
	Nonce    string `json:"nonce"`
	To       string `json:"to,omitempty"`
	Value    string `json:"value"`
	ChainId  string `json:"chainId"`
	V        string `json:"v"`
	R        string `json:"r"`
	S        string `json:"s"`
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

// MarshalBinary transforms the transaction into its binary representation
func (tx *EvmTx) MarshalBinary() ([]byte, error) {
	if !tx.Signed {
		return tx.SignBytes()
	}

	switch tx.Type {
	case EvmTxLegacy:
		f := tx.RlpFields()
		f = append(f, tx.Y, tx.R, tx.S)
		return rlp.EncodeValue(f)
	default:
		f := tx.RlpFields()
		f = append(f, tx.Y, tx.R, tx.S)
		buf, err := rlp.EncodeValue(f)
		if err != nil {
			return nil, err
		}
		return append([]byte{tx.typeValue()}, buf...), nil
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

// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (tx *EvmTx) UnmarshalBinary(buf []byte) error {
	return tx.ParseTransaction(buf)
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

func (tx *EvmTx) Signature() (*secp256k1.Signature, error) {
	if !tx.Signed {
		return nil, errors.New("cannot obtain signature of an unsigned transaction")
	}
	r := new(secp256k1.ModNScalar)
	if overflow := r.SetByteSlice(tx.R.Bytes()); overflow {
		return nil, errors.New("cannot read signature: invalid value for R >= group order")
	}
	s := new(secp256k1.ModNScalar)
	if overflow := s.SetByteSlice(tx.S.Bytes()); overflow {
		return nil, errors.New("cannot read signature: invalid value for S >= group order")
	}

	v := tx.Y.Uint64()
	if tx.Type == EvmTxLegacy {
		if v >= 35 {
			// EIP-155: v = ChainId * 2 + 35 + (v & 1)
			bit := 1 - (v & 1)
			v -= 35 + bit
			tx.ChainId = v / 2
			v = bit
		} else {
			tx.ChainId = 0
		}
	}
	return secp256k1.NewSignatureWithRecoveryCode(r, s, byte(v)), nil
}

func (tx *EvmTx) SenderPubkey() (*secp256k1.PublicKey, error) {
	if !tx.Signed {
		return nil, errors.New("cannot obtain signature of an unsigned transaction")
	}
	sig, err := tx.Signature()
	if err != nil {
		return nil, err
	}
	// RecoverCompact expects a signature inform V,R,S
	buf, err := tx.SignBytes()
	if err != nil {
		return nil, err
	}
	pub, err := sig.RecoverPublicKey(cryptutil.Hash(buf, sha3.NewLegacyKeccak256))
	if err != nil {
		return nil, err
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

func (tx *EvmTx) Sign(key crypto.Signer) error {
	buf, err := tx.SignBytes()
	if err != nil {
		return err
	}
	h := cryptutil.Hash(buf, sha3.NewLegacyKeccak256)
	sig, err := key.Sign(rand.Reader, h, crypto.Hash(0))
	if err != nil {
		return err
	}
	// expect sig to be in DER format
	sigO, err := secp256k1.ParseDERSignature(sig)
	if err != nil {
		return err
	}
	// find recovery bit
	sigO.BruteforceRecoveryCode(h, key.Public().(*secp256k1.PublicKey))
	// apply signature
	tx.Signed = true
	var v byte
	tx.R, tx.S, v = sigO.Export()
	if tx.Type == EvmTxLegacy {
		if tx.ChainId == 0 {
			// super-legacy
			tx.Y = big.NewInt(27 + int64(v))
		} else {
			// EIP-155: v = ChainId * 2 + 35 + (v & 1)
			tx.Y = big.NewInt(int64(tx.ChainId)*2 + 35 + int64(v))
		}
	} else {
		tx.Y = big.NewInt(int64(v))
	}
	return nil
}

func (tx *EvmTx) Hash() ([]byte, error) {
	data, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return cryptutil.Hash(data, sha3.NewLegacyKeccak256), nil
}

func (tx *EvmTx) MarshalJSON() ([]byte, error) {
	obj := &evmTxJson{
		Gas:      "0x" + strconv.FormatUint(tx.Gas, 16),
		GasPrice: "0x" + tx.GasFeeCap.Text(16),
		Input:    "0x" + hex.EncodeToString(tx.Data),
		Nonce:    "0x" + strconv.FormatUint(tx.Nonce, 16),
		To:       tx.To,
		Value:    "0x" + tx.Value.Text(16),
		ChainId:  "0x" + strconv.FormatUint(tx.ChainId, 16),
	}

	if tx.Signed {
		obj.From, _ = tx.SenderAddress()
		obj.V = "0x" + tx.Y.Text(16)
		obj.R = "0x" + tx.R.Text(16)
		obj.S = "0x" + tx.S.Text(16)
		//obj.Hash = cryptutil.Hash(tx.????, sha3.NewLegacyKeccak256)
	}
	return json.Marshal(obj)
}

func (tx *EvmTx) Call(method string, params ...any) error {
	res, err := EvmCall(method, params...)
	if err != nil {
		return err
	}
	tx.Data = res
	return nil
}
