package outscript

import (
	"encoding/binary"
	"fmt"
)

type IPushBytes struct {
	v Insertable
}

func (i IPushBytes) Bytes(s *Script) []byte {
	return pushBytes(i.v.Bytes(s))
}

func (i IPushBytes) String() string {
	return fmt.Sprintf("PushBytes(%s)", i.v)
}

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

func parsePushBytes(v []byte) []byte {
	if len(v) == 0 {
		return nil
	}
	p := v[0]
	v = v[1:]
	if p <= 75 {
		if len(v) >= int(p) {
			return v[:p]
		}
		// not enough data → error
		return nil
	}
	switch p {
	case 0x4c: // OP_PUSHDATA1
		p = v[0]
		v = v[1:]
		if len(v) >= int(p) {
			return v[:p]
		}
		// not enough data → error
		return nil
	case 0x4d: // OP_PUSHDATA2
		l := binary.LittleEndian.Uint16(v[:2])
		v = v[2:]
		if len(v) >= int(l) {
			return v[:l]
		}
		return nil
	case 0x4e: // OP_PUSHDATA4
		l := binary.LittleEndian.Uint32(v[:4])
		v = v[4:]
		if len(v) >= int(l) {
			return v[:l]
		}
		return nil
	default:
		return nil
	}
}
