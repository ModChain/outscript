package outscript_test

import (
	"encoding/hex"
	"log"
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

	log.Printf("tx = %+v", tx)
	log.Printf("addr = %s (expect ebe790e554f30924801b48197dcb6f71de2760bc)", must(tx.SenderAddress()))
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
