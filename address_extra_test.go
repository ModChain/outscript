package outscript_test

import (
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
	"github.com/ModChain/secp256k1"
)

func TestParseBitcoinAddress(t *testing.T) {
	// Deprecated wrapper, should work like ParseBitcoinBasedAddress("auto", ...)
	out, err := outscript.ParseBitcoinAddress("1C2yfT2NNAPPHBqXQxxBPvguht2whJWRSi")
	if err != nil {
		t.Fatalf("ParseBitcoinAddress failed: %s", err)
	}
	if out.Name != "p2pkh" {
		t.Errorf("expected p2pkh, got %s", out.Name)
	}
}

func TestParseBitcoinBasedAddressNetworks(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	s := outscript.New(key.PubKey())

	tests := []struct {
		format  string
		network string
	}{
		{"p2pkh", "bitcoin"},
		{"p2pkh", "litecoin"},
		{"p2pkh", "dogecoin"},
		{"p2pkh", "namecoin"},
		{"p2pkh", "monacoin"},
		{"p2pkh", "electraproto"},
		{"p2pkh", "dash"},
		{"p2pkh", "bitcoin-testnet"},
		{"p2sh:p2pkh", "bitcoin"},
		{"p2sh:p2pkh", "litecoin"},
		{"p2sh:p2pkh", "namecoin"},
		{"p2sh:p2pkh", "dogecoin"},
		{"p2sh:p2pkh", "monacoin"},
		{"p2sh:p2pkh", "electraproto"},
		{"p2sh:p2pkh", "dash"},
		{"p2sh:p2pkh", "bitcoin-testnet"},
		{"p2wpkh", "bitcoin"},
		{"p2wpkh", "litecoin"},
		{"p2wpkh", "monacoin"},
		{"p2wpkh", "electraproto"},
		{"p2wpkh", "bitcoin-testnet"},
	}

	for _, tc := range tests {
		sout, err := s.Out(tc.format)
		if err != nil {
			t.Errorf("Out(%s) failed: %s", tc.format, err)
			continue
		}
		addr, err := sout.Address(tc.network)
		if err != nil {
			t.Errorf("Address(%s, %s) failed: %s", tc.format, tc.network, err)
			continue
		}

		// Round-trip: parse the address back
		out, err := outscript.ParseBitcoinBasedAddress(tc.network, addr)
		if err != nil {
			t.Errorf("ParseBitcoinBasedAddress(%s, %s) failed: %s", tc.network, addr, err)
			continue
		}
		if out.Script != sout.Script {
			t.Errorf("round-trip mismatch for %s/%s: %s != %s", tc.format, tc.network, out.Script, sout.Script)
		}
	}
}

func TestParseBitcoinBasedAddressAutoDetect(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	s := outscript.New(key.PubKey())

	// Generate addresses with specific networks, then parse with auto-detect
	autoTests := []struct {
		format  string
		network string
	}{
		{"p2pkh", "dogecoin"},
		{"p2pkh", "namecoin"},
		{"p2pkh", "dash"},
		{"p2pkh", "bitcoin-testnet"},
		{"p2sh:p2pkh", "namecoin"},
		{"p2sh:p2pkh", "dogecoin"},
		{"p2sh:p2pkh", "dash"},
		{"p2sh:p2pkh", "bitcoin-testnet"},
	}

	for _, tc := range autoTests {
		sout, err := s.Out(tc.format)
		if err != nil {
			t.Errorf("Out(%s) failed: %s", tc.format, err)
			continue
		}
		addr, err := sout.Address(tc.network)
		if err != nil {
			t.Errorf("Address(%s, %s) failed: %s", tc.format, tc.network, err)
			continue
		}

		out, err := outscript.ParseBitcoinBasedAddress("auto", addr)
		if err != nil {
			t.Errorf("auto-detect ParseBitcoinBasedAddress(%s) failed: %s", addr, err)
			continue
		}
		if out.Script != sout.Script {
			t.Errorf("auto-detect round-trip mismatch for %s/%s", tc.format, tc.network)
		}
	}
}

func TestParseEvmAddressChecksum(t *testing.T) {
	// Valid checksummed address
	_, err := outscript.ParseEvmAddress("0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7")
	if err != nil {
		t.Errorf("valid checksummed address failed: %s", err)
	}

	// All lowercase (no checksum check)
	_, err = outscript.ParseEvmAddress("0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7")
	if err != nil {
		t.Errorf("lowercase address failed: %s", err)
	}

	// Bad checksum (wrong case)
	_, err = outscript.ParseEvmAddress("0x2AEB8ADD8337360E088B7D9ce4e857b9BE60f3a7")
	if err == nil {
		t.Error("expected error for bad checksum address")
	}

	// Too short
	_, err = outscript.ParseEvmAddress("0x1234")
	if err == nil {
		t.Error("expected error for short address")
	}

	// Invalid hex
	_, err = outscript.ParseEvmAddress("0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestScriptAddress(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	s := outscript.New(key.PubKey())

	// Script.Address is a convenience wrapper
	addr, err := s.Address("eth")
	if err != nil {
		t.Fatalf("Address(eth) failed: %s", err)
	}
	if addr != "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7" {
		t.Errorf("unexpected eth address: %s", addr)
	}

	addr, err = s.Address("p2pkh", "bitcoin")
	if err != nil {
		t.Fatalf("Address(p2pkh, bitcoin) failed: %s", err)
	}
	if addr != "1C2yfT2NNAPPHBqXQxxBPvguht2whJWRSi" {
		t.Errorf("unexpected p2pkh address: %s", addr)
	}
}

func TestParseBitcoinCashAddress(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	s := outscript.New(key.PubKey())

	// Generate a bitcoin-cash address
	sout, err := s.Out("p2pkh")
	if err != nil {
		t.Fatalf("Out(p2pkh) failed: %s", err)
	}
	addr, err := sout.Address("bitcoin-cash")
	if err != nil {
		t.Fatalf("Address(bitcoin-cash) failed: %s", err)
	}

	// Parse it back
	out, err := outscript.ParseBitcoinBasedAddress("bitcoin-cash", addr)
	if err != nil {
		t.Fatalf("ParseBitcoinBasedAddress(bitcoin-cash, %s) failed: %s", addr, err)
	}
	if out.Script != sout.Script {
		t.Errorf("round-trip mismatch for bitcoin-cash p2pkh")
	}

	// Also try without the prefix (auto-detect)
	if len(addr) > 12 {
		shortAddr := addr[len("bitcoincash:"):]
		out2, err := outscript.ParseBitcoinBasedAddress("auto", shortAddr)
		if err != nil {
			t.Fatalf("auto-detect short bitcoin-cash addr failed: %s", err)
		}
		if out2.Script != sout.Script {
			t.Errorf("auto-detect short addr mismatch")
		}
	}
}

func TestParseBitcoinBasedAddressP2SHNetworks(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	s := outscript.New(key.PubKey())

	// Bitcoin-cash P2SH
	sout, err := s.Out("p2sh:p2pkh")
	if err != nil {
		t.Fatalf("Out(p2sh:p2pkh) failed: %s", err)
	}
	addr, err := sout.Address("bitcoin-cash")
	if err != nil {
		t.Fatalf("Address(bitcoin-cash) p2sh failed: %s", err)
	}
	out, err := outscript.ParseBitcoinBasedAddress("bitcoin-cash", addr)
	if err != nil {
		t.Fatalf("ParseBitcoinBasedAddress(bitcoin-cash, p2sh) failed: %s", err)
	}
	if out.Name != "p2sh" {
		t.Errorf("expected p2sh, got %s", out.Name)
	}
}

func TestParseBitcoinBasedAddressErrors(t *testing.T) {
	// Unsupported network
	_, err := outscript.ParseBitcoinBasedAddress("unsupported-net", "1C2yfT2NNAPPHBqXQxxBPvguht2whJWRSi")
	if err == nil {
		t.Error("expected error for unsupported network")
	}

	// Completely invalid address
	_, err = outscript.ParseBitcoinBasedAddress("auto", "not-an-address!!!")
	if err == nil {
		t.Error("expected error for invalid address")
	}

	// Network mismatch for segwit
	_, err = outscript.ParseBitcoinBasedAddress("litecoin", "bc1q0yy3juscd3zfavw76g4h3eqdqzda7qyf58rj4m")
	if err == nil {
		t.Error("expected error for network mismatch on segwit address")
	}
}
