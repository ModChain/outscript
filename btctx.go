package outscript

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/KarpelesLab/cryptutil"
	"golang.org/x/crypto/ripemd160"
)

type BtcTx struct {
	Version  uint32         `json:"version"`
	In       []*BtcTxInput  `json:"vin"`
	Out      []*BtcTxOutput `json:"vout"`
	Locktime uint32         `json:"locktime"`
}
type Hex32 [32]byte

func (h Hex32) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h[:]))
}

func (h Hex32) UnmarshalJSON(v []byte) error {
	if string(v) == "null" {
		return nil
	}
	var s string
	err := json.Unmarshal(v, &s)
	if err != nil {
		return err
	}
	bin, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(bin) != 32 {
		return errors.New("bitcoin hex32 must be 32 bytes long (64 hex chars)")
	}
	copy(h[:], bin)
	return nil
}

type BtcTxInput struct {
	TXID      Hex32
	Vout      uint32
	Script    []byte
	Sequence  uint32
	Witnesses [][]byte
}

type BtcTxOutput struct {
	Amount BtcAmount
	N      int // not stored
	Script []byte
}

type BtcTxSign struct {
	Key     crypto.Signer
	Options crypto.SignerOpts
	Scheme  string    // "p2pk", etc
	Amount  BtcAmount // value of input, required for segwit transaction signing
	SigHash uint32
}

// Sign will perform signature on the transaction
func (tx *BtcTx) Sign(keys ...*BtcTxSign) error {
	if len(tx.In) == 0 || len(tx.In) != len(keys) {
		return errors.New("Sign requires as many keys as there are inputs")
	}

	wtx := tx.Dup() // work tx, used for signing/etc
	var pfx, sfx []byte
	var err error

	for n, k := range keys {
		if k.SigHash == 0 {
			k.SigHash = 1 // default to SIGHASH_ALL
		}
		if k.Options == nil {
			k.Options = crypto.SHA256
		}

		switch k.Scheme {
		case "p2pk":
			wtx.ClearInputs()
			wtx.In[n].Script, err = New(k.Key.Public()).Generate("p2pk")
			if err != nil {
				return err
			}
			buf := wtx.exportBytes(false)
			buf = binary.LittleEndian.AppendUint32(buf, k.SigHash)
			signHash := cryptutil.Hash(buf, sha256.New, sha256.New)
			sign, err := k.Key.Sign(rand.Reader, signHash, k.Options)
			if err != nil {
				return err
			}
			sign = append(sign, byte(k.SigHash&0xff))
			tx.In[n].Script = PushBytes(sign)
		case "p2pkh", "p2pukh":
			if k.SigHash&0x40 == 0x40 {
				// bitcoin-cash style sig. the preimage is the same as segwit
				if pfx == nil {
					pfx, sfx = tx.preimage()
				}
				err := tx.p2wpkhSign(n, k, pfx, sfx)
				if err != nil {
					return err
				}
				break
			}
			wtx.ClearInputs()
			wtx.In[n].Script, err = New(k.Key.Public()).Generate(k.Scheme)
			if err != nil {
				return err
			}
			buf := wtx.exportBytes(false)
			buf = binary.LittleEndian.AppendUint32(buf, k.SigHash)
			signHash := cryptutil.Hash(buf, sha256.New, sha256.New)
			sign, err := k.Key.Sign(rand.Reader, signHash, k.Options)
			if err != nil {
				return err
			}
			sign = append(sign, byte(k.SigHash&0xff))
			var pubkey []byte
			if k.Scheme == "p2pkh" {
				pubkey, err = New(k.Key.Public()).Generate("pubkey:comp")
			} else {
				pubkey, err = New(k.Key.Public()).Generate("pubkey:uncomp")
			}
			if err != nil {
				return err
			}
			tx.In[n].Script = slices.Concat(PushBytes(sign), PushBytes(pubkey))
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
	var pubKey []byte
	var err error

	if k.Scheme == "p2pukh" {
		pubKey, err = New(k.Key.Public()).Generate("pubkey:uncomp")
	} else {
		pubKey, err = New(k.Key.Public()).Generate("pubkey:comp")
	}
	if err != nil {
		return err
	}
	input, inputSeq := tx.In[n].preimageBytes()
	pkHash := cryptutil.Hash(pubKey, sha256.New, ripemd160.New)
	scriptCode := append(append([]byte{0x76, 0xa9}, PushBytes(pkHash)...), 0x88, 0xac)
	amount := binary.LittleEndian.AppendUint64(nil, uint64(k.Amount))

	// perform signature
	signString := slices.Concat(pfx, input, PushBytes(scriptCode), amount, inputSeq, sfx)
	signString = binary.LittleEndian.AppendUint32(signString, k.SigHash)
	signHash := cryptutil.Hash(signString, sha256.New, sha256.New)
	sign, err := k.Key.Sign(rand.Reader, signHash, k.Options)
	if err != nil {
		return err
	}
	sign = append(sign, byte(k.SigHash&0xff))

	switch k.Scheme {
	case "p2pkh", "p2pukh":
		// segwit preimage-style signature, as used by bitcoincash with forkid
		tx.In[n].Script = slices.Concat(PushBytes(sign), PushBytes(pubKey))
	case "p2wpkh":
		tx.In[n].Witnesses = [][]byte{sign, pubKey}
		tx.In[n].Script = nil
	case "p2sh:p2wpkh":
		tx.In[n].Witnesses = [][]byte{sign, pubKey}
		// 1716001479091972186c449eb1ded22b78e40d009bdf0089
		tx.In[n].Script = PushBytes(append([]byte{0}, PushBytes(pkHash)...))
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
	return tx.AddNetOutput("auto", address, amount)
}

// AddNetOutput adds the specified address as an output to the transaction. The address will be parsed for the given
// network and an error will be returned if the address is not valid. Passing "auto" as network name disables all
// checks and it is up to the caller to confirm the address and resulting output is valid first.
func (tx *BtcTx) AddNetOutput(network, address string, amount uint64) error {
	addr, err := ParseBitcoinBasedAddress(network, address)
	if err != nil {
		return err
	}
	out := &BtcTxOutput{
		Amount: BtcAmount(amount),
		N:      len(tx.Out),
		Script: addr.raw,
	}
	tx.Out = append(tx.Out, out)
	return nil
}

// Dup duplicates a transaction and its inputs/outputs
func (tx *BtcTx) Dup() *BtcTx {
	res := &BtcTx{
		Version:  tx.Version,
		In:       make([]*BtcTxInput, len(tx.In)),
		Out:      make([]*BtcTxOutput, len(tx.Out)),
		Locktime: tx.Locktime,
	}
	for n, in := range tx.In {
		res.In[n] = in.Dup()
	}
	for n, out := range tx.Out {
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

// EstimateSize computes the transaction size, taking into account specific rules for segwit.
func (tx *BtcTx) ComputeSize() int {
	// a tx contains fixed parts: version (4 bytes), number of inputs (1 byte usually), number of outputs (1 byte usually), locktime (4 bytes)
	ln := 4 + BtcVarInt(len(tx.In)).Len() + BtcVarInt(len(tx.Out)).Len() + 4
	witln := 0

	for _, in := range tx.In {
		ln += in.computeSize()
		witln += in.computeWitnessSize()
	}

	for _, out := range tx.Out {
		ln += out.computeSize()
	}

	if witln == 0 {
		return ln
	}

	witln += 2 // marker, flag

	// witness data counts as 0.25 per byte, but we want to ceil it, check if it's divisible or not
	add := witln % 4
	if add != 0 {
		add = 1
	}

	return ln + witln/4 + add
}

// exportBytes returns the bytes data for a given transaction
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
		tx.Out[n] = &BtcTxOutput{N: n}
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

func (in *BtcTxInput) computeSize() int {
	return 32 + 4 + BtcVarInt(len(in.Script)).Len() + len(in.Script) + 4
}

func (in *BtcTxInput) computeWitnessSize() int {
	ln := BtcVarInt(len(in.Witnesses)).Len()
	for _, b := range in.Witnesses {
		ln += BtcVarInt(len(b)).Len() + len(b)
	}
	return ln
}

func (in *BtcTxInput) Bytes() []byte {
	// txid + vout + script_len + script + seq
	txid := slices.Clone(in.TXID[:])
	slices.Reverse(txid)
	buf := binary.LittleEndian.AppendUint32(txid, in.Vout)
	buf = append(buf, BtcVarInt(len(in.Script)).Bytes()...)
	buf = append(buf, in.Script...)
	buf = binary.LittleEndian.AppendUint32(buf, in.Sequence)
	return buf
}

// preimageBytes returns the bytes used for this transaction for segwit pre-imaging
func (in *BtcTxInput) preimageBytes() ([]byte, []byte) {
	// txid + vout only
	txid := slices.Clone(in.TXID[:])
	slices.Reverse(txid)
	return binary.LittleEndian.AppendUint32(txid, in.Vout), binary.LittleEndian.AppendUint32(nil, in.Sequence)
}

// rawTXID returns TXID with its bytes reversed, as it appears on the network
func (in *BtcTxInput) rawTXID() []byte {
	txid := slices.Clone(in.TXID[:])
	slices.Reverse(txid)
	return txid
}

var (
	prefillEmptySig       = make([]byte, 72) // maximum length of DER signature with sighash
	prefillEmptyCompKey   = make([]byte, 33) // 03+compressed key
	prefillEmptyUncompKey = make([]byte, 65) // 04+uncomp key
	prefillP2PK           = PushBytes(prefillEmptySig)
	prefillP2PKH          = slices.Concat(PushBytes(prefillEmptySig), PushBytes(prefillEmptyCompKey))
	prefillP2PUKH         = slices.Concat(PushBytes(prefillEmptySig), PushBytes(prefillEmptyUncompKey))
	prefillP2WPKH         = [][]byte{prefillEmptySig, prefillEmptyCompKey}
)

// Prefill will fill the transaction input with empty data matching the expected signature length for the given scheme, if supported
func (in *BtcTxInput) Prefill(scheme string) error {
	switch scheme {
	case "p2pk":
		in.Script = prefillP2PK
		return nil
	case "p2pkh":
		in.Script = prefillP2PKH
		return nil
	case "p2pukh":
		in.Script = prefillP2PUKH
		return nil
	case "p2wpkh":
		in.Script = nil
		in.Witnesses = prefillP2WPKH
		return nil
	default:
		return fmt.Errorf("unsupported sign scheme: %s", scheme)
	}
}

func (in *BtcTxInput) ReadFrom(r io.Reader) (int64, error) {
	h := &readHelper{R: r}
	h.readFull(in.TXID[:])
	slices.Reverse(in.TXID[:])
	in.Vout = h.readUint32le()
	in.Script = h.readVarBuf()
	in.Sequence = h.readUint32le()
	return h.ret()
}

func (in *BtcTxInput) Dup() *BtcTxInput {
	res := &BtcTxInput{}
	*res = *in
	res.Script = slices.Clone(res.Script)
	res.Witnesses = make([][]byte, len(in.Witnesses))
	for n, w := range in.Witnesses {
		res.Witnesses[n] = slices.Clone(w)
	}
	return res
}

func (out *BtcTxOutput) computeSize() int {
	return 8 + BtcVarInt(len(out.Script)).Len() + len(out.Script)
}

func (out *BtcTxOutput) Bytes() []byte {
	buf := binary.LittleEndian.AppendUint64(nil, uint64(out.Amount))
	buf = append(buf, BtcVarInt(len(out.Script)).Bytes()...)
	buf = append(buf, out.Script...)
	return buf
}

// ReadFrom parses a transaction output from the provided reader.
func (out *BtcTxOutput) ReadFrom(r io.Reader) (int64, error) {
	h := &readHelper{R: r}
	out.Amount = BtcAmount(h.readUint64le())
	out.Script = h.readVarBuf()
	return h.ret()
}

// Dup returns a copy of the BtcTxOutput object; used for transaction signing.
func (out *BtcTxOutput) Dup() *BtcTxOutput {
	res := &BtcTxOutput{}
	*res = *out
	return res
}

type btxTxInputJson struct {
	TXID      string                `json:"txid"`
	Vout      uint32                `json:"vout"`
	ScriptSig *btxTxInputScriptJson `json:"scriptSig"`
	Sequence  uint32                `json:"sequence"`
	Witnesses []string              `json:"witnesses,omitempty"`
}

type btxTxInputScriptJson struct {
	Hex string `json:"hex"`
}

func (in *BtcTxInput) MarshalJSON() ([]byte, error) {
	o := &btxTxInputJson{
		TXID: hex.EncodeToString(in.TXID[:]),
		Vout: in.Vout,
		ScriptSig: &btxTxInputScriptJson{
			Hex: hex.EncodeToString(in.Script),
		},
		Sequence: in.Sequence,
	}
	for _, w := range in.Witnesses {
		o.Witnesses = append(o.Witnesses, hex.EncodeToString(w))
	}
	return json.Marshal(o)
}

type btxTxOutputJson struct {
	Value  BtcAmount              `json:"value"`
	N      int                    `json:"n"`
	Script *btxTxOutputScriptJson `json:"scriptPubKey"`
}

type btxTxOutputScriptJson struct {
	Hex       string   `json:"hex"`
	Type      string   `json:"type"`
	Addresses []string `json:"addresses,omitempty"`
}

func (out *BtcTxOutput) MarshalJSON() ([]byte, error) {
	o := &btxTxOutputJson{
		Value: out.Amount,
		N:     out.N,
		Script: &btxTxOutputScriptJson{
			Hex: hex.EncodeToString(out.Script),
			// TODO
		},
	}

	return json.Marshal(o)
}

func (out *BtcTxOutput) UnmarshalJSON(b []byte) error {
	var o *btxTxOutputJson
	if string(b) == "null" {
		return nil
	}
	err := json.Unmarshal(b, &o)
	if err != nil {
		return err
	}
	out.Amount = o.Value
	out.N = o.N
	if o.Script == nil {
		out.Script = nil
		return nil
	}
	out.Script, err = hex.DecodeString(o.Script.Hex)
	if err != nil {
		return err
	}
	return nil
}

type BtcAmount uint64

func (b BtcAmount) MarshalJSON() ([]byte, error) {
	// return amount as a float, always 8 decimals
	s := strconv.FormatUint(uint64(b), 10)
	ln := len(s)
	if ln <= 8 {
		// add zeroes
		s = strings.Repeat("0", 9-ln) + s
		ln = 9
	}
	// we now know that len(s) >= 9, cut it so we add a zero
	s = s[:ln-8] + "." + s[ln-8:]
	return []byte(s), nil
}

func (ba *BtcAmount) UnmarshalJSON(b []byte) error {
	// locate dot position
	s := string(b)
	if s == "null" {
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	pos := strings.IndexByte(s, '.')
	if pos == -1 {
		// no dot means this is an int, multiply it by 100000000
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return err
		}
		v = v * 1_0000_0000
		*ba = BtcAmount(v)
		return nil
	}
	// we have a ., it should be at len(s)-8 ideally, but let's be flexible
	// we will not allow more than 8 decimals however
	ln := len(s)
	decCount := ln - pos - 1
	if decCount > 8 {
		return errors.New("cannot parse amount with more than 8 decimals")
	}
	s = s[:pos] + s[pos+1:] // without the dot
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	for decCount < 8 {
		// multiply by 10 until decCount==8
		decCount += 1
		v *= 10
	}
	*ba = BtcAmount(v)
	return nil
}
