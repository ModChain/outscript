package outscript_test

import (
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestParseMassaAddressInvalidPrefix(t *testing.T) {
	_, err := outscript.ParseMassaAddress("XX12345678901234567890")
	if err == nil {
		t.Error("expected error for invalid prefix")
	}
}

func TestParseMassaAddressInvalidBase58(t *testing.T) {
	_, err := outscript.ParseMassaAddress("AU!!!invalid!!!")
	if err == nil {
		t.Error("expected error for invalid base58")
	}
}
