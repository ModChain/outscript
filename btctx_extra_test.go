package outscript_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/KarpelesLab/outscript"
	"github.com/ModChain/secp256k1"
)

func TestBtcTxMarshalBinary(t *testing.T) {
	txBin := must(hex.DecodeString("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"))
	tx := &outscript.BtcTx{}
	_, err := tx.ReadFrom(bytes.NewReader(txBin))
	if err != nil {
		t.Fatalf("ReadFrom failed: %s", err)
	}

	marshaled, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %s", err)
	}
	if !bytes.Equal(txBin, marshaled) {
		t.Error("MarshalBinary round-trip mismatch")
	}
}

func TestBtcTxUnmarshalBinary(t *testing.T) {
	txBin := must(hex.DecodeString("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"))
	tx := &outscript.BtcTx{}
	err := tx.UnmarshalBinary(txBin)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed: %s", err)
	}
	if tx.Version != 1 {
		t.Errorf("expected version 1, got %d", tx.Version)
	}
	if len(tx.In) != 1 {
		t.Errorf("expected 1 input, got %d", len(tx.In))
	}
	if len(tx.Out) != 2 {
		t.Errorf("expected 2 outputs, got %d", len(tx.Out))
	}
}

func TestBtcTxAddOutput(t *testing.T) {
	tx := &outscript.BtcTx{Version: 1}
	err := tx.AddOutput("1C2yfT2NNAPPHBqXQxxBPvguht2whJWRSi", 50000)
	if err != nil {
		t.Fatalf("AddOutput failed: %s", err)
	}
	if len(tx.Out) != 1 {
		t.Fatalf("expected 1 output, got %d", len(tx.Out))
	}
	if tx.Out[0].Amount != 50000 {
		t.Errorf("expected amount 50000, got %d", tx.Out[0].Amount)
	}
}

func TestBtcTxAddNetOutput(t *testing.T) {
	tx := &outscript.BtcTx{Version: 1}

	// Bitcoin p2pkh
	err := tx.AddNetOutput("bitcoin", "1C2yfT2NNAPPHBqXQxxBPvguht2whJWRSi", 100000)
	if err != nil {
		t.Fatalf("AddNetOutput(bitcoin) failed: %s", err)
	}

	// Bitcoin segwit
	err = tx.AddNetOutput("bitcoin", "bc1q0yy3juscd3zfavw76g4h3eqdqzda7qyf58rj4m", 200000)
	if err != nil {
		t.Fatalf("AddNetOutput(bitcoin segwit) failed: %s", err)
	}

	if len(tx.Out) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(tx.Out))
	}

	// Invalid address should error
	err = tx.AddNetOutput("bitcoin", "not-an-address", 100000)
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestBtcTxInputMarshalJSON(t *testing.T) {
	txBin := must(hex.DecodeString("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"))
	tx := &outscript.BtcTx{}
	_ = tx.UnmarshalBinary(txBin)

	data, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("MarshalJSON tx failed: %s", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestBtcTxOutputUnmarshalJSONNull(t *testing.T) {
	var out outscript.BtcTxOutput
	err := out.UnmarshalJSON([]byte("null"))
	if err != nil {
		t.Errorf("UnmarshalJSON null failed: %s", err)
	}
}

func TestBtcTxSignP2PKH(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))

	txHex := "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
	tx := &outscript.BtcTx{}
	_ = tx.UnmarshalBinary(must(hex.DecodeString(txHex)))

	err := tx.Sign(&outscript.BtcTxSign{Key: key, Scheme: "p2pkh", Amount: 1000000000})
	if err != nil {
		t.Fatalf("Sign p2pkh failed: %s", err)
	}
	if len(tx.In[0].Script) == 0 {
		t.Error("expected non-empty script after p2pkh signing")
	}
}

func TestBtcTxPrefillSchemes(t *testing.T) {
	schemes := []struct {
		name      string
		hasScript bool
		witCount  int
	}{
		{"p2pk", true, 0},
		{"p2pkh", true, 0},
		{"p2pukh", true, 0},
		{"p2wpkh", false, 2},
		{"p2wsh:p2pk", false, 2},
		{"p2wsh:p2puk", false, 2},
		{"p2wsh:p2pkh", false, 3},
		{"p2wsh:p2pukh", false, 3},
		{"p2wsh", false, 3},
	}

	for _, tc := range schemes {
		in := &outscript.BtcTxInput{}
		err := in.Prefill(tc.name)
		if err != nil {
			t.Errorf("Prefill(%s) failed: %s", tc.name, err)
			continue
		}
		if tc.hasScript && len(in.Script) == 0 {
			t.Errorf("Prefill(%s): expected non-empty script", tc.name)
		}
		if !tc.hasScript && in.Script != nil {
			t.Errorf("Prefill(%s): expected nil script", tc.name)
		}
		if len(in.Witnesses) != tc.witCount {
			t.Errorf("Prefill(%s): expected %d witnesses, got %d", tc.name, tc.witCount, len(in.Witnesses))
		}
	}

	// Unsupported scheme
	in := &outscript.BtcTxInput{}
	err := in.Prefill("unsupported")
	if err == nil {
		t.Error("expected error for unsupported prefill scheme")
	}
}

func TestHex32MarshalJSON(t *testing.T) {
	h := outscript.Hex32{}
	for i := range h {
		h[i] = byte(i)
	}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("Hex32 MarshalJSON failed: %s", err)
	}
	if string(data) != `"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"` {
		t.Errorf("unexpected Hex32 JSON: %s", data)
	}
}
