package outscript

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/KarpelesLab/cryptutil"
	"golang.org/x/crypto/ripemd160"
)

type BtcTx struct {
	Version  uint32
	In       []*BtcTxInput
	Out      []*BtcTxOutput
	Locktime uint32
}

type BtcTxInput struct {
	TXID      [32]byte
	Vout      uint32
	Script    []byte
	Sequence  uint32
	Witnesses [][]byte
}

type BtcTxOutput struct {
	Amount uint64
	Script []byte
}

type BtcTxSign struct {
	Key     crypto.Signer
	Scheme  string // "p2pk", etc
	Amount  uint64 // value of input, required for segwit transaction signing
	SigHash uint32
}

// Sign will perform signature on the transaction
func (tx *BtcTx) Sign(keys ...*BtcTxSign) error {
	if len(tx.In) == 0 || len(tx.In) != len(keys) {
		return errors.New("Sign requires as many keys as there are inputs")
	}

	wtx := tx.Dup() // work tx, used for signing/etc
	var pfx, sfx []byte

	for n, k := range keys {
		if k.SigHash == 0 {
			k.SigHash = 1 // default to SIGHASH_ALL
		}

		switch k.Scheme {
		case "p2pk":
			wtx.ClearInputs()
			wtx.In[n].Script = New(k.Key.Public().(PublicKeyIntf)).Generate("p2pk")
			buf := wtx.exportBytes(false)
			buf = binary.LittleEndian.AppendUint32(buf, k.SigHash)
			signHash := cryptutil.Hash(buf, sha256.New, sha256.New)
			sign, err := k.Key.Sign(rand.Reader, signHash, crypto.SHA256)
			if err != nil {
				return err
			}
			sign = append(sign, byte(k.SigHash&0xff))
			tx.In[n].Script = pushBytes(sign)
		case "p2wpkh", "p2sh:p2wpkh":
			if pfx == nil {
				pfx, sfx = tx.preimage()
			}

			err := tx.p2wpkhSign(n, k, pfx, sfx)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported sign scheme: %s", k.Scheme)
		}
	}
	return nil
}

func (tx *BtcTx) p2wpkhSign(n int, k *BtcTxSign, pfx, sfx []byte) error {
	if pfx == nil {
		pfx, sfx = tx.preimage()
	}

	// prepare values for segwit signature
	pubKey := k.Key.Public().(PublicKeyIntf).SerializeCompressed()
	input, inputSeq := tx.In[n].preimageBytes()
	pkHash := cryptutil.Hash(pubKey, sha256.New, ripemd160.New)
	scriptCode := append(append([]byte{0x76, 0xa9}, pushBytes(pkHash)...), 0x88, 0xac)
	amount := binary.LittleEndian.AppendUint64(nil, k.Amount)

	// perform signature
	signString := slices.Concat(pfx, input, pushBytes(scriptCode), amount, inputSeq, sfx)
	signString = binary.LittleEndian.AppendUint32(signString, k.SigHash)
	signHash := cryptutil.Hash(signString, sha256.New, sha256.New)
	sign, err := k.Key.Sign(rand.Reader, signHash, crypto.SHA256)
	if err != nil {
		return err
	}
	sign = append(sign, byte(k.SigHash&0xff))

	tx.In[n].Witnesses = [][]byte{sign, pubKey}
	switch k.Scheme {
	case "p2wpkh":
		tx.In[n].Script = nil
	case "p2sh:p2wpkh":
		// 1716001479091972186c449eb1ded22b78e40d009bdf0089
		tx.In[n].Script = pushBytes(append([]byte{0}, pushBytes(pkHash)...))
	}
	return nil
}

// preimage computes the segwit preimage prefix/suffix. The return parts are in brackets below:
//
//	preimage = [version + hash256(inputs) + hash256(sequences)] + input + scriptcode + amount + sequence + [hash256(outputs) + locktime]
func (tx *BtcTx) preimage() ([]byte, []byte) {
	vers := binary.LittleEndian.AppendUint32(nil, tx.Version)
	inputsA := sha256.New()
	inputsB := sha256.New()
	for _, in := range tx.In {
		a, b := in.preimageBytes()
		inputsA.Write(a)
		inputsB.Write(b)
	}

	prefix := slices.Concat(vers, cryptutil.Hash(inputsA.Sum(nil), sha256.New), cryptutil.Hash(inputsB.Sum(nil), sha256.New))

	outputs := sha256.New()
	for _, out := range tx.Out {
		outputs.Write(out.Bytes())
	}
	locktime := binary.LittleEndian.AppendUint32(nil, tx.Locktime)

	suffix := slices.Concat(cryptutil.Hash(outputs.Sum(nil), sha256.New), locktime)

	return prefix, suffix
}

func (tx *BtcTx) MarshalBinary() ([]byte, error) {
	return tx.Bytes(), nil
}

func (tx *BtcTx) Bytes() []byte {
	return tx.exportBytes(tx.HasWitness())
}

func (tx *BtcTx) HasWitness() bool {
	for _, in := range tx.In {
		if len(in.Witnesses) > 0 {
			return true
		}
	}
	return false
}

// AddOutput adds the specified address as an output to the transaction. Note that this will not check if the output
// is valid for a given network, this is up to the caller to confirm things first.
func (tx *BtcTx) AddOutput(address string, amount uint64) error {
	addr, err := ParseBitcoinAddress(address)
	if err != nil {
		return err
	}
	out := &BtcTxOutput{
		Amount: amount,
		Script: addr.raw,
	}
	tx.Out = append(tx.Out, out)
	return nil
}

// Dup duplicates a transaction and its inputs/outputs
func (tx *BtcTx) Dup() *BtcTx {
	res := &BtcTx{}
	*res = *tx
	for n, in := range res.In {
		res.In[n] = in.Dup()
	}
	for n, out := range res.Out {
		res.Out[n] = out.Dup()
	}
	return res
}

// ClearInputs removes all the input scripts and witnesses from the transaction. Used during signing.
func (tx *BtcTx) ClearInputs() {
	for _, in := range tx.In {
		in.Script = nil
		in.Witnesses = nil
	}
}

func (tx *BtcTx) exportBytes(wit bool) []byte {
	buf := binary.LittleEndian.AppendUint32(nil, tx.Version)
	if wit {
		// make this a witness tx
		buf = append(buf, 0, 1) // marker, flags
	}
	buf = append(buf, BtcVarInt(len(tx.In)).Bytes()...)
	for _, in := range tx.In {
		buf = append(buf, in.Bytes()...)
	}
	buf = append(buf, BtcVarInt(len(tx.Out)).Bytes()...)
	for _, out := range tx.Out {
		buf = append(buf, out.Bytes()...)
	}
	if wit {
		for _, in := range tx.In {
			buf = append(buf, BtcVarInt(len(in.Witnesses)).Bytes()...)
			for _, b := range in.Witnesses {
				buf = append(buf, BtcVarInt(len(b)).Bytes()...)
				buf = append(buf, b...)
			}
		}
	}
	buf = binary.LittleEndian.AppendUint32(buf, tx.Locktime)
	return buf
}

func (tx *BtcTx) Hash() ([]byte, error) {
	h := cryptutil.Hash(tx.exportBytes(false), sha256.New, sha256.New)
	slices.Reverse(h)
	return h, nil
}

func (tx *BtcTx) UnmarshalBinary(buf []byte) error {
	_, err := tx.ReadFrom(bytes.NewReader(buf))
	return err
}

func (tx *BtcTx) ReadFrom(r io.Reader) (int64, error) {
	h := &readHelper{R: r}
	tx.Version = h.readUint32le()
	var inCnt BtcVarInt
	h.readTo(&inCnt)
	segwit := false
	if inCnt == 0 {
		// likely segwit tx
		segwit = true
		h.readByte() // segwit flag, not sure what to do with this for now

		// this time we should have the right number of inputs
		h.readTo(&inCnt)
	}
	if inCnt > 10000 {
		return h.err(errors.New("invalid transaction: too many inputs"))
	}
	tx.In = make([]*BtcTxInput, inCnt)
	for n := range tx.In {
		tx.In[n] = &BtcTxInput{}
		h.readTo(tx.In[n])
	}
	var outCnt BtcVarInt
	h.readTo(&outCnt)
	if outCnt > 65536 {
		return h.err(errors.New("invalid transaction: too many inputs"))
	}
	tx.Out = make([]*BtcTxOutput, outCnt)
	for n := range tx.Out {
		tx.Out[n] = &BtcTxOutput{}
		h.readTo(tx.Out[n])
	}
	if segwit {
		for _, in := range tx.In {
			var witnessCnt BtcVarInt
			h.readTo(&witnessCnt)
			in.Witnesses = make([][]byte, witnessCnt)
			for n := range in.Witnesses {
				in.Witnesses[n] = h.readVarBuf()
			}
		}
	}
	tx.Locktime = h.readUint32le()
	return h.ret()
}

func (in *BtcTxInput) Bytes() []byte {
	// txid + vout + script_len + script + seq
	buf := binary.LittleEndian.AppendUint32(in.TXID[:], in.Vout)
	buf = append(buf, BtcVarInt(len(in.Script)).Bytes()...)
	buf = append(buf, in.Script...)
	buf = binary.LittleEndian.AppendUint32(buf, in.Sequence)
	return buf
}

// preimageBytes returns the bytes used for this transaction for segwit pre-imaging
func (in *BtcTxInput) preimageBytes() ([]byte, []byte) {
	// txid + vout only
	return binary.LittleEndian.AppendUint32(in.TXID[:], in.Vout), binary.LittleEndian.AppendUint32(nil, in.Sequence)
}

func (in *BtcTxInput) ReadFrom(r io.Reader) (int64, error) {
	h := &readHelper{R: r}
	h.readFull(in.TXID[:])
	in.Vout = h.readUint32le()
	in.Script = h.readVarBuf()
	in.Sequence = h.readUint32le()
	return h.ret()
}

func (in *BtcTxInput) Dup() *BtcTxInput {
	res := &BtcTxInput{}
	*res = *in
	return res
}

func (out *BtcTxOutput) Bytes() []byte {
	buf := binary.LittleEndian.AppendUint64(nil, out.Amount)
	buf = append(buf, BtcVarInt(len(out.Script)).Bytes()...)
	buf = append(buf, out.Script...)
	return buf
}

// ReadFrom parses a transaction output from the provided reader.
func (out *BtcTxOutput) ReadFrom(r io.Reader) (int64, error) {
	h := &readHelper{R: r}
	out.Amount = h.readUint64le()
	out.Script = h.readVarBuf()
	return h.ret()
}

// Dup returns a copy of the BtcTxOutput object; used for transaction signing.
func (out *BtcTxOutput) Dup() *BtcTxOutput {
	res := &BtcTxOutput{}
	*res = *out
	return res
}
