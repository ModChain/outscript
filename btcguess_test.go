package outscript_test

import (
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestGuessOut(t *testing.T) {
	// 76a9149e8985f82bc4e0f753d0492aa8d11cc39925774088ac
	a, b := outscript.GuessPubKeyAndHashByOutScript(must(hex.DecodeString("76a9149e8985f82bc4e0f753d0492aa8d11cc39925774088ac")))

	if a != nil || hex.EncodeToString(b) != "9e8985f82bc4e0f753d0492aa8d11cc399257740" {
		t.Errorf("invalid result for GuessPubKeyAndHashByOutScript")
	}
}
