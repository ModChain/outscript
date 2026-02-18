package outscript_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestMassaAddress(t *testing.T) {
	key := ed25519.NewKeyFromSeed(must(hex.DecodeString("20a1c9d559159085c82ae54e35f332a2d54aab952dd5832c42d06fb0548d5f88")))
	s := outscript.New(key.Public())

	testV := []addrTestV{
		addrTestV{"massa", "massa", "AU16f3K8uWS8cSJaXb7oDzKUZRqt7392eFPtq2bBBop9PVbyXkMs"},
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
		out, err = outscript.ParseMassaAddress(tv.addr)
		if err != nil {
			t.Errorf("failed to parse %s: %s", tv.addr, err)
		} else if out.Script != sout.Script {
			t.Errorf("script did not match for addr %s", tv.addr)
		}
	}
}
