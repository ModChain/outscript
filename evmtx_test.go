package outscript_test

import (
	"encoding/hex"
	"testing"

	"github.com/ModChain/outscript"
)

func TestEvmTx(t *testing.T) {
	// https://etherscan.io/tx/0xbac4cb10f95b37dab2c8a78e880d39661cc53f87386ded2fb721ac2304113ea3
	// (last transaction of block 12345678, randomly chosen for that reason and because it's a legacy tx)
	// Sender = 0xebe790e554f30924801b48197dcb6f71de2760bc
	txBin := must(hex.DecodeString("f86b1e8507ea8ed4008252089443badf0e63ac147ace611dc1113afe0ea3f8691787d529ae9e8600008026a0cacce90eb140f837a139e5d8acbe73527663aea163d4e4c6e8218681d1d37b0fa07fdb860517234804b71bbc518ecb4dc4bb96c1944ab28d502fc429baac939b3c"))
	tx := &outscript.EvmTx{}
	err := tx.ParseTransaction(txBin)
	if err != nil {
		t.Errorf("failed to parse tx: %s", err)
	}

	//log.Printf("tx = %+v", tx)
	if must(tx.SenderAddress()) != "0xebE790E554f30924801B48197DCb6f71de2760BC" {
		t.Errorf("unexpected sender, wanted 0xebE790E554f30924801B48197DCb6f71de2760BC")
	}
}

func TestEvmTx1559(t *testing.T) {
	// https://etherscan.io/tx/0xc0c7f78587ebe1f3b377f9c572fe59f4007c88677a1bbd78349f7356304e06b4
	// (tx that happened to be there when I opened etherscan)
	// Sender = 0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97
	txBin := must(hex.DecodeString("02f87101830bdfbb80850243e1963982798e94e866fecdb429c72c30868d3582192a878298698487d3c0ba13571e2080c080a08032999a5ae9477f5f52134c9dc1690d1e25d0bb78ef0f22b949afd0df73a9e4a07106563a788499eb370a48e7c86c08e357866fcc12867a8c530b5ca22175e784"))
	tx := &outscript.EvmTx{}
	err := tx.ParseTransaction(txBin)
	if err != nil {
		t.Errorf("failed to parse tx: %s", err)
	}

	//log.Printf("tx = %+v", tx)
	if must(tx.SenderAddress()) != "0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97" {
		t.Errorf("unexpected sender, wanted 0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
