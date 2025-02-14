package outscript_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ModChain/outscript"
	"github.com/ModChain/secp256k1"
)

type addrTestV struct {
	fmt  string // eg: p2pkh
	net  string // eg: bitcoin
	addr string
}

func TestAddresses(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	s := outscript.New(key.PubKey())

	// NOTE: those addresses have their private key right here in the source. DO NOT USE THESE EVER

	testV := []addrTestV{
		addrTestV{"eth", "ethereum", "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7"},
		addrTestV{"p2pkh", "bitcoin", "1C2yfT2NNAPPHBqXQxxBPvguht2whJWRSi"},
		addrTestV{"p2pkh", "bitcoincash", "bitcoincash:qpusjxtjrpkyf843mmfzk78yp5qfhhcq3yv38ma5lm"},
		addrTestV{"p2pkh", "litecoin", "LWFvvfLCSpdSXzXgb6wUfwkfv6QDipAzJc"},
		addrTestV{"p2sh:p2pkh", "litecoin", "MNBNbudWqRT5MhorGVnpk7DDuMX5XCxKnR"},
		addrTestV{"p2wpkh", "bitcoin", "bc1q0yy3juscd3zfavw76g4h3eqdqzda7qyf58rj4m"},
		addrTestV{"p2wpkh", "litecoin", "ltc1q0yy3juscd3zfavw76g4h3eqdqzda7qyfsmekdt"},
		addrTestV{"p2wsh:p2wpkh", "bitcoin", "bc1qwg7r0yn6t7ctfaplxuwvlu2yk8q6fd3xsvr3lkq5ud4ylsecczzqgq9ste"},
	}

	var out *outscript.Out

	for _, tv := range testV {
		sout, err := s.Out(tv.fmt)
		if err != nil {
			t.Errorf("failed to generate %s: %s", tv.addr, err)
			continue
		}
		addr, err := sout.Address(tv.net)
		if err != nil {
			t.Errorf("failed to generate %s: %s", tv.addr, err)
		} else if addr != tv.addr {
			t.Errorf("unexpected addr: %s != %s", addr, tv.addr)
		}

		// re-gen out from addr
		if strings.HasPrefix(tv.addr, "0x") {
			out, err = outscript.ParseEvmAddress(tv.addr)
		} else {
			out, err = outscript.ParseBitcoinBasedAddress("auto", tv.addr)
		}
		if err != nil {
			t.Errorf("failed to parse %s: %s", tv.addr, err)
		} else if out.Script != sout.Script {
			t.Errorf("script did not match for addr %s", tv.addr)
		}
	}
}

func TestTaprootAddr(t *testing.T) {
	// we can't generate taproot addrs but should be able to parse one
	a := "bc1pgf6m46mr8c55veujxg3qvqxfektwmmpfrt5mhwtvwrzeacmm7xaqdndj5l" // found in the wild

	addr, err := outscript.ParseBitcoinBasedAddress("bitcoin", a)
	if err != nil {
		t.Errorf("could not parse taproot: %s", err)
		return
	}

	b, err := addr.Address()
	if err != nil {
		t.Errorf("taproot address encode fail: %s", err)
		return
	}
	if b != a {
		t.Errorf("address marshal does not work for taproot")
	}
}
