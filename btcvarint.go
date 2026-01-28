package outscript

import (
	"encoding/binary"
	"io"
)

// BtcVarInt is a Bitcoin variable-length integer as defined in the Bitcoin protocol.
// Values 0-0xfc are stored as a single byte; larger values use a prefix byte
// (0xfd, 0xfe, or 0xff) followed by 2, 4, or 8 bytes respectively in little-endian order.
type BtcVarInt uint64

// Bytes returns the encoded variable-length integer as a byte slice.
func (v BtcVarInt) Bytes() []byte {
	switch {
	case v <= 0xfc:
		return []byte{byte(v)}
	case v <= 0xffff:
		return binary.LittleEndian.AppendUint16([]byte{0xfd}, uint16(v))
	case v <= 0xffffffff:
		return binary.LittleEndian.AppendUint32([]byte{0xfe}, uint32(v))
	default:
		return binary.LittleEndian.AppendUint64([]byte{0xff}, uint64(v))
	}
}

// Len returns the number of bytes needed to encode this variable-length integer.
func (v BtcVarInt) Len() int {
	switch {
	case v <= 0xfc:
		return 1
	case v <= 0xffff:
		return 3
	case v <= 0xffffffff:
		return 5
	default:
		return 9
	}
}

// ReadFrom reads a variable-length integer from r.
func (v *BtcVarInt) ReadFrom(r io.Reader) (int64, error) {
	h := &readHelper{R: r}
	t := h.readByte()

	if t <= 0xfc {
		// as is
		*v = BtcVarInt(t)
		return h.ret()
	}
	switch t {
	case 0xfd:
		*v = BtcVarInt(h.readUint16le())
	case 0xfe:
		*v = BtcVarInt(h.readUint32le())
	case 0xff:
		*v = BtcVarInt(h.readUint64le())
	}
	return h.ret()
}

// WriteTo writes the encoded variable-length integer to w.
func (v BtcVarInt) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(v.Bytes())
	return int64(n), err
}
