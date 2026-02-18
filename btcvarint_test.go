package outscript_test

import (
	"bytes"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestBtcVarIntSmall(t *testing.T) {
	v := outscript.BtcVarInt(42)
	b := v.Bytes()
	if len(b) != 1 || b[0] != 42 {
		t.Errorf("expected [42], got %v", b)
	}
	if v.Len() != 1 {
		t.Errorf("expected Len()=1, got %d", v.Len())
	}

	var v2 outscript.BtcVarInt
	_, err := v2.ReadFrom(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("ReadFrom failed: %s", err)
	}
	if v2 != 42 {
		t.Errorf("round-trip mismatch: got %d", v2)
	}
}

func TestBtcVarIntMax1Byte(t *testing.T) {
	v := outscript.BtcVarInt(0xfc)
	b := v.Bytes()
	if len(b) != 1 {
		t.Errorf("expected 1 byte, got %d", len(b))
	}
	if v.Len() != 1 {
		t.Errorf("expected Len()=1, got %d", v.Len())
	}
}

func TestBtcVarInt2Bytes(t *testing.T) {
	v := outscript.BtcVarInt(0xfd)
	b := v.Bytes()
	if len(b) != 3 || b[0] != 0xfd {
		t.Errorf("expected 3 bytes with prefix 0xfd, got %v", b)
	}
	if v.Len() != 3 {
		t.Errorf("expected Len()=3, got %d", v.Len())
	}

	var v2 outscript.BtcVarInt
	_, err := v2.ReadFrom(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("ReadFrom failed: %s", err)
	}
	if v2 != 0xfd {
		t.Errorf("round-trip mismatch: got %d", v2)
	}
}

func TestBtcVarInt0xFFFF(t *testing.T) {
	v := outscript.BtcVarInt(0xffff)
	b := v.Bytes()
	if len(b) != 3 {
		t.Errorf("expected 3 bytes, got %d", len(b))
	}

	var v2 outscript.BtcVarInt
	_, err := v2.ReadFrom(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("ReadFrom failed: %s", err)
	}
	if v2 != 0xffff {
		t.Errorf("round-trip mismatch: got %d", v2)
	}
}

func TestBtcVarInt4Bytes(t *testing.T) {
	v := outscript.BtcVarInt(0x10000)
	b := v.Bytes()
	if len(b) != 5 || b[0] != 0xfe {
		t.Errorf("expected 5 bytes with prefix 0xfe, got %v (len=%d)", b, len(b))
	}
	if v.Len() != 5 {
		t.Errorf("expected Len()=5, got %d", v.Len())
	}

	var v2 outscript.BtcVarInt
	_, err := v2.ReadFrom(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("ReadFrom failed: %s", err)
	}
	if v2 != 0x10000 {
		t.Errorf("round-trip mismatch: got %d", v2)
	}
}

func TestBtcVarInt8Bytes(t *testing.T) {
	v := outscript.BtcVarInt(0x100000000)
	b := v.Bytes()
	if len(b) != 9 || b[0] != 0xff {
		t.Errorf("expected 9 bytes with prefix 0xff, got len=%d", len(b))
	}
	if v.Len() != 9 {
		t.Errorf("expected Len()=9, got %d", v.Len())
	}

	var v2 outscript.BtcVarInt
	_, err := v2.ReadFrom(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("ReadFrom failed: %s", err)
	}
	if v2 != 0x100000000 {
		t.Errorf("round-trip mismatch: got %d", v2)
	}
}

func TestBtcVarIntWriteTo(t *testing.T) {
	v := outscript.BtcVarInt(300)
	var buf bytes.Buffer
	n, err := v.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %s", err)
	}
	if n != 3 {
		t.Errorf("expected 3 bytes written, got %d", n)
	}

	var v2 outscript.BtcVarInt
	_, err = v2.ReadFrom(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrom failed: %s", err)
	}
	if v2 != 300 {
		t.Errorf("round-trip mismatch: got %d", v2)
	}
}
