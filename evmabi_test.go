package outscript_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestEvmScript(t *testing.T) {
	// transfer(address recipient, uint256 amount)
	buf := &outscript.AbiBuffer{}
	err := buf.EncodeAuto(must(outscript.ParseEvmAddress("0x5Fb84129AD9E7818F099966de975ff41213F028d")), new(big.Int).SetUint64(123456789123456789))
	if err != nil {
		t.Errorf("encoding error: %s", err)
		return
	}
	call := buf.Call("transfer(address,uint256)")
	if hex.EncodeToString(call) != "a9059cbb0000000000000000000000005fb84129ad9e7818f099966de975ff41213f028d00000000000000000000000000000000000000000000000001b69b4bacd05f15" {
		t.Errorf("call encoded data unexpected result, got %x", call)
	}

	call2, err := outscript.EvmCall("castVoteWithReason(uint256,uint8,string)", 123456789123456789, 1, "this is a test")
	if err != nil {
		t.Errorf("encoding error: %s", err)
		return
	}
	if hex.EncodeToString(call2) != "7b3c71d300000000000000000000000000000000000000000000000001b69b4bacd05f1500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000e7468697320697320612074657374000000000000000000000000000000000000" {
		// can test the decoding on https://tools.deth.net/calldata-decoder (remember to add 0x in front of the calldata)
		t.Errorf("castVoteWithReason test call error, got %x", call2)
	}
}
