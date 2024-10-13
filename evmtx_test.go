package outscript_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ModChain/outscript"
	"github.com/ModChain/secp256k1"
)

func TestEvmTxLegacy(t *testing.T) {
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

func TestEvmTxSign(t *testing.T) {
	// generate a simple legacy tx
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))
	//addr := outscript.New(key.Public().(outscript.PublicKeyIntf)).Generate("eth")

	tx := &outscript.EvmTx{ChainId: 1, Nonce: 42, GasFeeCap: big.NewInt(30000000000), Gas: 21000, To: "0x2aeb8add8337360e088b7d9ce4e857b9be60f3a7", Value: new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)}

	//log.Printf("eth addr = %x", addr) // 2aeb8add8337360e088b7d9ce4e857b9be60f3a7

	err := tx.Sign(key)
	if err != nil {
		t.Errorf("signature failed: %s", err)
	}

	if must(tx.SenderAddress()) != "0x2AeB8ADD8337360E088B7D9ce4e857b9BE60f3a7" {
		t.Errorf("unexpected evmtx sender addr: %s", must(tx.SenderAddress()))
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
