package outscript

import "encoding/binary"

func pushBytes(v []byte) []byte {
	// see: https://en.bitcoin.it/wiki/Script
	if len(v) <= 75 {
		return append([]byte{byte(len(v))}, v...)
	}
	if len(v) <= 0xff {
		return append([]byte{0x4c, byte(len(v))}, v...) // OP_PUSHDATA1
	}
	if len(v) <= 0xffff {
		var op [3]byte
		op[0] = 0x4d // OP_PUSHDATA2
		binary.LittleEndian.PutUint16(op[1:], uint16(len(v)))
		return append(op[:], v...)
	}
	// really?
	var op [5]byte
	op[0] = 0x4e // OP_PUSHDATA4
	binary.LittleEndian.PutUint32(op[1:], uint32(len(v)))
	return append(op[:], v...)
}
