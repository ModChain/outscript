package outscript_test

import (
	"math/big"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestNewAbiBuffer(t *testing.T) {
	buf := outscript.NewAbiBuffer(nil)
	if buf == nil {
		t.Fatal("NewAbiBuffer returned nil")
	}
	result := buf.Bytes()
	if len(result) != 0 {
		t.Errorf("expected empty bytes, got %d bytes", len(result))
	}
}

func TestAbiEncodeAutoTypes(t *testing.T) {
	buf := outscript.NewAbiBuffer(nil)

	// int
	err := buf.EncodeAuto(42)
	if err != nil {
		t.Fatalf("EncodeAuto(int) failed: %s", err)
	}

	// int64
	buf = outscript.NewAbiBuffer(nil)
	err = buf.EncodeAuto(int64(100))
	if err != nil {
		t.Fatalf("EncodeAuto(int64) failed: %s", err)
	}

	// uint64
	buf = outscript.NewAbiBuffer(nil)
	err = buf.EncodeAuto(uint64(200))
	if err != nil {
		t.Fatalf("EncodeAuto(uint64) failed: %s", err)
	}

	// *big.Int
	buf = outscript.NewAbiBuffer(nil)
	err = buf.EncodeAuto(big.NewInt(300))
	if err != nil {
		t.Fatalf("EncodeAuto(*big.Int) failed: %s", err)
	}

	// []byte
	buf = outscript.NewAbiBuffer(nil)
	err = buf.EncodeAuto([]byte("hello"))
	if err != nil {
		t.Fatalf("EncodeAuto([]byte) failed: %s", err)
	}

	// string
	buf = outscript.NewAbiBuffer(nil)
	err = buf.EncodeAuto("world")
	if err != nil {
		t.Fatalf("EncodeAuto(string) failed: %s", err)
	}

	// unsupported type
	buf = outscript.NewAbiBuffer(nil)
	err = buf.EncodeAuto(3.14)
	if err == nil {
		t.Error("expected error for unsupported type float64")
	}
}

func TestAbiEncodeAutoEvmAddress(t *testing.T) {
	out, err := outscript.ParseEvmAddress("0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7")
	if err != nil {
		t.Fatalf("ParseEvmAddress failed: %s", err)
	}

	buf := outscript.NewAbiBuffer(nil)
	err = buf.EncodeAuto(out)
	if err != nil {
		t.Fatalf("EncodeAuto(*Out eth) failed: %s", err)
	}
	result := buf.Bytes()
	if len(result) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(result))
	}
}

func TestAbiEncodeTypesUintVariants(t *testing.T) {
	buf := outscript.NewAbiBuffer(nil)
	// Test various uint types, bytes types
	err := buf.EncodeTypes(
		[]string{"uint8", "uint16", "uint32", "uint64", "uint256", "uint", "bytes4", "bytes32"},
		big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4),
		big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8),
	)
	if err != nil {
		t.Fatalf("EncodeTypes failed: %s", err)
	}
	result := buf.Bytes()
	if len(result) != 8*32 {
		t.Errorf("expected %d bytes, got %d", 8*32, len(result))
	}
}

func TestAbiEncodeTypesBytesAndString(t *testing.T) {
	buf := outscript.NewAbiBuffer(nil)
	err := buf.EncodeTypes(
		[]string{"bytes", "string"},
		[]byte("hello"), "world",
	)
	if err != nil {
		t.Fatalf("EncodeTypes(bytes,string) failed: %s", err)
	}
	result := buf.Bytes()
	if len(result) == 0 {
		t.Error("expected non-empty result")
	}
}

func TestAbiEncodeTypesUnsupported(t *testing.T) {
	buf := outscript.NewAbiBuffer(nil)
	err := buf.EncodeTypes([]string{"tuple"}, 42)
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestAbiEncodeTypesWrongCount(t *testing.T) {
	buf := outscript.NewAbiBuffer(nil)
	err := buf.EncodeTypes([]string{"uint256", "uint256"}, big.NewInt(1))
	if err == nil {
		t.Error("expected error for wrong parameter count")
	}
}

func TestAbiEncodeAbiInvalid(t *testing.T) {
	buf := outscript.NewAbiBuffer(nil)

	// Missing parentheses
	err := buf.EncodeAbi("noparens", big.NewInt(1))
	if err == nil {
		t.Error("expected error for missing parentheses")
	}

	// Missing closing paren
	err = buf.EncodeAbi("func(uint256", big.NewInt(1))
	if err == nil {
		t.Error("expected error for missing closing parenthesis")
	}
}

func TestAppendBigIntOverflow(t *testing.T) {
	buf := outscript.NewAbiBuffer(nil)
	// Value larger than 2^256 should fail
	huge := new(big.Int).Lsh(big.NewInt(1), 257)
	err := buf.AppendBigInt(huge)
	if err == nil {
		t.Error("expected error for value exceeding 256 bits")
	}
}

func TestAppendUint256AnyBool(t *testing.T) {
	buf := outscript.NewAbiBuffer(nil)
	err := buf.AppendUint256Any(true)
	if err != nil {
		t.Fatalf("AppendUint256Any(true) failed: %s", err)
	}

	buf = outscript.NewAbiBuffer(nil)
	err = buf.AppendUint256Any(false)
	if err != nil {
		t.Fatalf("AppendUint256Any(false) failed: %s", err)
	}

	// Unsupported type
	buf = outscript.NewAbiBuffer(nil)
	err = buf.AppendUint256Any("not a number")
	if err == nil {
		t.Error("expected error for unsupported type in AppendUint256Any")
	}
}

func TestAppendBufferAnyTypes(t *testing.T) {
	buf := outscript.NewAbiBuffer(nil)
	err := buf.AppendBufferAny([]byte("data"))
	if err != nil {
		t.Fatalf("AppendBufferAny([]byte) failed: %s", err)
	}

	buf = outscript.NewAbiBuffer(nil)
	err = buf.AppendBufferAny("data")
	if err != nil {
		t.Fatalf("AppendBufferAny(string) failed: %s", err)
	}

	buf = outscript.NewAbiBuffer(nil)
	err = buf.AppendBufferAny(42)
	if err == nil {
		t.Error("expected error for unsupported type in AppendBufferAny")
	}
}

func TestEvmCallWithParam(t *testing.T) {
	data, err := outscript.EvmCall("balanceOf(uint256)", big.NewInt(1))
	if err != nil {
		t.Fatalf("EvmCall failed: %s", err)
	}
	// 4-byte selector + 32-byte param
	if len(data) != 36 {
		t.Errorf("expected 36 bytes, got %d", len(data))
	}
}

func TestEvmCallError(t *testing.T) {
	_, err := outscript.EvmCall("bad-abi")
	if err == nil {
		t.Error("expected error for invalid ABI")
	}
}
