package outscript

import "encoding"

var (
	_ = Transaction(&EvmTx{})
	_ = Transaction(&BtcTx{})
)

type Transaction interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}
