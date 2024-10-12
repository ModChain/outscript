package outscript

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"slices"

	"github.com/KarpelesLab/cryptutil"
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

func (tx *BtcTx) Hash() []byte {
	h := cryptutil.Hash(tx.exportBytes(false), sha256.New, sha256.New)
	slices.Reverse(h)
	return h
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

func (in *BtcTxInput) ReadFrom(r io.Reader) (int64, error) {
	h := &readHelper{R: r}
	h.readFull(in.TXID[:])
	in.Vout = h.readUint32le()
	in.Script = h.readVarBuf()
	in.Sequence = h.readUint32le()
	return h.ret()
}

func (out *BtcTxOutput) Bytes() []byte {
	buf := binary.LittleEndian.AppendUint64(nil, out.Amount)
	buf = append(buf, BtcVarInt(len(out.Script)).Bytes()...)
	buf = append(buf, out.Script...)
	return buf
}

func (out *BtcTxOutput) ReadFrom(r io.Reader) (int64, error) {
	h := &readHelper{R: r}
	out.Amount = h.readUint64le()
	out.Script = h.readVarBuf()
	return h.ret()
}
