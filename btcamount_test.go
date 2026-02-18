package outscript_test

import (
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestBtcAmountUnmarshalTextDecimal(t *testing.T) {
	tests := []struct {
		input string
		want  outscript.BtcAmount
	}{
		{"1.5", 150000000},
		{"0.00000001", 1},
		{"21000000.00000000", 2100000000000000},
		{"0.1", 10000000},
		{"100", 10000000000},
	}

	for _, tc := range tests {
		var ba outscript.BtcAmount
		err := ba.UnmarshalText([]byte(tc.input))
		if err != nil {
			t.Errorf("UnmarshalText(%q) failed: %s", tc.input, err)
			continue
		}
		if ba != tc.want {
			t.Errorf("UnmarshalText(%q) = %d, want %d", tc.input, ba, tc.want)
		}
	}
}

func TestBtcAmountUnmarshalTextHex(t *testing.T) {
	var ba outscript.BtcAmount
	err := ba.UnmarshalText([]byte("0x5f5e100"))
	if err != nil {
		t.Fatalf("UnmarshalText hex failed: %s", err)
	}
	if ba != 100000000 {
		t.Errorf("expected 100000000, got %d", ba)
	}
}

func TestBtcAmountUnmarshalTextInteger(t *testing.T) {
	var ba outscript.BtcAmount
	err := ba.UnmarshalText([]byte("50"))
	if err != nil {
		t.Fatalf("UnmarshalText integer failed: %s", err)
	}
	if ba != 5000000000 {
		t.Errorf("expected 5000000000, got %d", ba)
	}
}

func TestBtcAmountUnmarshalTextTooManyDecimals(t *testing.T) {
	var ba outscript.BtcAmount
	err := ba.UnmarshalText([]byte("1.123456789"))
	if err == nil {
		t.Error("expected error for >8 decimals, got nil")
	}
}

func TestBtcAmountUnmarshalJSONNull(t *testing.T) {
	var ba outscript.BtcAmount
	err := ba.UnmarshalJSON([]byte("null"))
	if err != nil {
		t.Errorf("UnmarshalJSON null failed: %s", err)
	}
}

func TestBtcAmountUnmarshalJSONQuoted(t *testing.T) {
	var ba outscript.BtcAmount
	err := ba.UnmarshalJSON([]byte(`"1.5"`))
	if err != nil {
		t.Fatalf("UnmarshalJSON quoted failed: %s", err)
	}
	if ba != 150000000 {
		t.Errorf("expected 150000000, got %d", ba)
	}
}
