package outscript

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/KarpelesLab/cryptutil"
	"golang.org/x/crypto/sha3"
)

// EVM ABI Encoding/decoding functions

var big2pow32 = new(big.Int).SetBit(new(big.Int), 256, 1) // maximum value of uint256+1

type abiString struct {
	offset int
	data   []byte
}

type AbiBuffer struct {
	buf []byte
	str []*abiString // strings to be encoded
}

func NewAbiBuffer(buf []byte) *AbiBuffer {
	return &AbiBuffer{buf: buf}
}

// EncodeAuto will encode a bunch of any values into whatever makes sense
// for the format they are. *big.Int will become uint256, *Script will become
// addresses, strings and []byte becomes bytes.
//
// Non-compact format is fairly simple since all numeric values are uint256
// (including addresses), and only strings/byte arrays are offsets to the end
// of the buffer where these are stored as length+data+padding
func (buf *AbiBuffer) EncodeAuto(params ...any) error {
	for _, param := range params {
		switch o := param.(type) {
		case int:
			if err := buf.AppendBigInt(new(big.Int).SetInt64(int64(o))); err != nil {
				return err
			}
		case int64:
			if err := buf.AppendBigInt(new(big.Int).SetInt64(o)); err != nil {
				return err
			}
		case uint64:
			if err := buf.AppendBigInt(new(big.Int).SetUint64(o)); err != nil {
				return err
			}
		case *big.Int:
			if err := buf.AppendBigInt(o); err != nil {
				return err
			}
		case []byte:
			buf.AppendBytes(o)
		case string:
			buf.AppendBytes([]byte(o))
		case *Out:
			if o.Name == "evm" || o.Name == "eth" {
				// ethereum address
				buf.AppendBigInt(new(big.Int).SetBytes(o.raw))
			} else {
				return fmt.Errorf("unsupported value type %s for EVM", o.Name)
			}
		default:
			return fmt.Errorf("unsupported value type %T", o)
		}
	}
	return nil
}

// EncodeAbi takes as first parameter an abi such as "transfer(address,uint256)" and
// a matching number of parameters.
func (buf *AbiBuffer) EncodeAbi(abi string, params ...any) error {
	// we expect abi to be func(a,b,c) where func is a string we do not really care about
	pos := strings.IndexByte(abi, '(')
	if pos == -1 {
		return errors.New("invalid abi format (could not locate start of parameters)")
	}
	if !strings.HasSuffix(abi, ")") {
		return errors.New("invalid abi format (does not end with a closing parenthesis)")
	}
	abiParams := abi[pos+1 : len(abi)-1]

	return buf.EncodeTypes(strings.Split(abiParams, ","), params...)
}

func (buf *AbiBuffer) EncodeTypes(types []string, params ...any) error {
	if len(types) != len(params) {
		return errors.New("wrong number of arguments")
	}
	if len(types) == 0 {
		return nil
	}

	for n, t := range types {
		switch t {
		case "uint", "uint8", "uint16", "uint32", "uint64", "uint256", "bytes4", "bytes32":
			err := buf.AppendUint256Any(params[n])
			if err != nil {
				return err
			}
		case "address":
			err := buf.AppendAddressAny(params[n])
			if err != nil {
				return err
			}
		case "bytes", "string":
			err := buf.AppendBufferAny(params[n])
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported type: %s", t)
		}
	}
	return nil
}

// AppendBigInt appends a big.Int value to the buffer
func (buf *AbiBuffer) AppendBigInt(v *big.Int) error {
	var inbuf [32]byte
	// should we modulo instead?
	if v.Sign() < 0 {
		v = new(big.Int).Sub(big2pow32, v) // if o = -1, it will be set to all 1s (proper negative value for -1 in 256 bits)
		if v.Sign() <= 0 {
			return errors.New("big.Int value exceeds negative 256 bits")
		}
	}
	if v.Cmp(big2pow32) >= 0 {
		return errors.New("big.Int value exceeds 256 bits")
	}
	v.FillBytes(inbuf[:])
	buf.buf = append(buf.buf, inbuf[:]...)
	return nil
}

// AppendBytes adds a byte buffer as parameter (which will be actually an offset to a later area)
func (buf *AbiBuffer) AppendBytes(v []byte) {
	var inbuf [32]byte
	pos := len(buf.buf)
	buf.buf = append(buf.buf, inbuf[:]...)
	new(big.Int).SetUint64(uint64(len(v))).FillBytes(inbuf[:])
	buf.str = append(buf.str, &abiString{offset: pos, data: append(inbuf[:], v...)})
}

func (buf *AbiBuffer) AppendUint256Any(v any) error {
	switch o := v.(type) {
	case bool:
		if o {
			return buf.AppendBigInt(new(big.Int).SetUint64(1))
		} else {
			return buf.AppendBigInt(new(big.Int).SetUint64(0))
		}
	case int:
		return buf.AppendBigInt(new(big.Int).SetInt64(int64(o)))
	case *big.Int:
		return buf.AppendBigInt(o)
	default:
		return fmt.Errorf("unsupported go type %T for evm abi uint256-style type", o)
	}
}

func (buf *AbiBuffer) AppendAddressAny(v any) error {
	switch o := v.(type) {
	default:
		return fmt.Errorf("unsupported go type %T for evm abi type address", o)
	}
}

func (buf *AbiBuffer) AppendBufferAny(v any) error {
	switch o := v.(type) {
	case []byte:
		buf.AppendBytes(o)
		return nil
	case string:
		buf.AppendBytes([]byte(o))
		return nil
	default:
		return fmt.Errorf("unsupported go type %T for evm abi buffer type", o)
	}
}

// Bytes will return the encoded ABI buffer
func (buf *AbiBuffer) Bytes() []byte {
	res := slices.Clone(buf.buf)

	for _, s := range buf.str {
		in := s.data
		x := len(in) % 32
		if x != 0 {
			// pad
			in = append(in, make([]byte, 32-x)...)
		}
		pos := new(big.Int).SetUint64(uint64(len(res)))
		pos.FillBytes(res[s.offset : s.offset+32])
		res = append(res, in...)
	}

	return res
}

// Call returns a EVM abi-encoded method call
func (buf *AbiBuffer) Call(method string) []byte {
	mHash := cryptutil.Hash([]byte(method), sha3.NewLegacyKeccak256)

	return append(mHash[:4], buf.Bytes()...)
}

// EvmCall generates calldata for a given EVM call, performing absolutely no check on the provided parameters
// as to whether these match the ABI or not.
func EvmCall(method string, params ...any) ([]byte, error) {
	buf := &AbiBuffer{}
	err := buf.EncodeAbi(method, params...)
	if err != nil {
		return nil, err
	}
	return buf.Call(method), nil
}
