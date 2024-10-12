package outscript

import (
	"encoding/binary"
	"errors"
	"io"
)

type readHelper struct {
	N   int64
	R   io.Reader
	Err error
}

func (rc *readHelper) readByte() byte {
	if rc.Err != nil {
		return 0
	}

	if r, ok := rc.R.(io.ByteReader); ok {
		v, err := r.ReadByte()
		if err != nil {
			rc.Err = err
			return 0
		}
		rc.N += 1
		return v
	}

	var res [1]byte
	n, err := io.ReadFull(rc.R, res[:])
	rc.N += int64(n)
	if err != nil {
		rc.Err = err
	}
	return res[0]
}

func (rc *readHelper) readUint16le() uint16 {
	var res [2]byte
	rc.readFull(res[:])
	return binary.LittleEndian.Uint16(res[:])
}

func (rc *readHelper) readUint32le() uint32 {
	var res [4]byte
	rc.readFull(res[:])
	return binary.LittleEndian.Uint32(res[:])
}

func (rc *readHelper) readUint64le() uint64 {
	var res [8]byte
	rc.readFull(res[:])
	return binary.LittleEndian.Uint64(res[:])
}

func (rc *readHelper) readFull(buf []byte) {
	if rc.Err != nil {
		return
	}

	n, err := io.ReadFull(rc.R, buf)
	rc.N += int64(n)
	if err != nil {
		rc.Err = err
	}
}

func (rc *readHelper) readTo(d io.ReaderFrom) {
	if rc.Err != nil {
		return
	}
	n, err := d.ReadFrom(rc.R)
	rc.N += n
	if err != nil {
		rc.Err = err
	}
}

func (rc *readHelper) readVarBuf() []byte {
	if rc.Err != nil {
		return nil
	}
	var ln BtcVarInt
	rc.readTo(&ln)
	if ln == 0 {
		return nil
	}
	if ln > 100000 {
		rc.Err = errors.New("error: buffer larger than maximum allowed length")
		return nil
	}
	buf := make([]byte, ln)
	rc.readFull(buf)
	return buf
}

func (rc *readHelper) err(err error) (int64, error) {
	return rc.N, err
}

func (rc *readHelper) ret() (int64, error) {
	return rc.N, rc.Err
}
