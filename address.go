package outscript

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/KarpelesLab/cryptutil"
	"github.com/ModChain/base58"
	"github.com/ModChain/bech32m"
)

// ParseEvmAddress parses an address to return an Out, supporting various
// networks.
func ParseEvmAddress(address string) (*Out, error) {
	if len(address) != 42 || !strings.HasPrefix(address, "0x") {
		return nil, errors.New("EVM addresses must be 42 characters long and start with 0x")
	}

	// that's an easy one
	data, err := hex.DecodeString(address[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ethereum address: %w", err)
	}
	if address != strings.ToLower(address) {
		if address != eip55(data) {
			return nil, fmt.Errorf("bad checksum on ethereum address")
		}
	}
	// all good
	return &Out{Name: "eth", Script: hex.EncodeToString(data), raw: data, Flags: []string{"evm"}}, nil
}

// ParseBitcoinAddress parses an address in bitcoin format and returns the matching script,
// accepting also other networks addresses (in which cash a flag will be set)
func ParseBitcoinAddress(address string) (*Out, error) {
	// case 1: bech32 address
	if strings.HasPrefix(address, "bitcoincash:") {
		typ, buf, err := bech32m.CashAddrDecode("bitcoincash:", address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bitcoin cash address: %s", err)
		}
		switch typ {
		case 0:
			// P2PKH
			script := slices.Concat([]byte{0x76, 0xa9}, pushBytes(buf), []byte{0x88, 0xac})
			out := makeOut("p2pkh", script, "bitcoincash")
			return out, nil
		case 1:
			// P2SH
			script := slices.Concat([]byte{0xa9}, pushBytes(buf), []byte{0x87})
			out := makeOut("p2sh", script, "bitcoincash")
			return out, nil
		default:
			return nil, fmt.Errorf("unsupported bitcoincash address type %d", typ)
		}
	}
	// attempt to decode as segwit addr
	pos := strings.LastIndexByte(address, '1')
	if pos > 0 {
		hrp := address[:pos]
		typ, buf, err := bech32m.SegwitAddrDecode(hrp, address)
		if err == nil {
			// this is a segwit addr!
			net := "bitcoin"
			switch hrp {
			case "ltc":
				net = "litecoin"
			case "bc":
				net = "bitcoin"
			default:
				return nil, fmt.Errorf("unsupported hrp value %s", hrp)
			}
			if typ != 0 {
				return nil, fmt.Errorf("unsupported segwit type %d", typ)
			}
			switch len(buf) {
			case 20:
				// P2WPKH
				script := slices.Concat([]byte{0x00}, pushBytes(buf))
				return makeOut("p2wpkh", script, net), nil
			case 32:
				// p2wsh
				script := slices.Concat([]byte{0x00}, pushBytes(buf))
				return makeOut("p2wsh", script, net), nil
			default:
				return nil, fmt.Errorf("invalid segwit address length %d", len(buf))
			}
		}
	}

	// decode as base58
	buf, err := base58.Bitcoin.Decode(address)
	if err == nil {
		// check hash
		chk := buf[len(buf)-4:]
		buf = buf[:len(buf)-4]
		h := cryptutil.Hash(buf, sha256.New, sha256.New)
		if subtle.ConstantTimeCompare(h[:4], chk) != 1 {
			err = errors.New("bad checksum")
		}
	}
	if err == nil {
		// https://en.bitcoin.it/wiki/List_of_address_prefixes
		// 1Fw9zL4vzCaf8yCqz1kinoU6N71hcmJyvD 0x00
		// 36WzxPKBV4ScwUKLPgmMZkphf7Np4rqjyo 0x05
		// LYSJKD6D9robFvCVTq3ZqgCNoCYgPFmyLs 0x30 litecoin p2pkh
		// MANDhrctLRAygo3dFckfWvEaWeQiti143C 0x32 litecoin p2sh
		switch buf[0] {
		case 0x00: // btc standard p2pkh, possibly bitcoincash
			script := slices.Concat([]byte{0x76, 0xa9}, pushBytes(buf[1:]), []byte{0x88, 0xac})
			out := makeOut("p2pkh", script, "bitcoin", "bitcoincash")
			return out, nil
		case 0x05: // btc p2sh
			script := slices.Concat([]byte{0xa9}, pushBytes(buf[1:]), []byte{0x87})
			out := makeOut("p2sh", script, "bitcoin", "bitcoincash")
			return out, nil
		case 0x16: // dogecoin p2sh
			script := slices.Concat([]byte{0xa9}, pushBytes(buf[1:]), []byte{0x87})
			out := makeOut("p2sh", script, "dogecoin")
			return out, nil
		case 0x1e: // dogecoin p2pkh
			script := slices.Concat([]byte{0x76, 0xa9}, pushBytes(buf[1:]), []byte{0x88, 0xac})
			out := makeOut("p2pkh", script, "dogecoin")
			return out, nil
		case 0x30: // litecoin p2pkh
			script := slices.Concat([]byte{0x76, 0xa9}, pushBytes(buf[1:]), []byte{0x88, 0xac})
			out := makeOut("p2pkh", script, "litecoin")
			return out, nil
		case 0x32: // litecoin p2sh
			script := slices.Concat([]byte{0xa9}, pushBytes(buf[1:]), []byte{0x87})
			out := makeOut("p2sh", script, "litecoin")
			return out, nil
		default:
			return nil, fmt.Errorf("unsupported base58 address version=%x", buf[0])
		}
	}

	return nil, fmt.Errorf("unsupported address %s", address)
}

func (out *Out) baseName() string {
	name := out.Name
	pos := strings.IndexByte(name, ':')
	if pos >= 0 {
		return name[:pos]
	}
	return name
}

func encodeBase58addr(vers byte, buf []byte) string {
	buf = slices.Concat([]byte{vers}, buf)
	h := cryptutil.Hash(buf, sha256.New, sha256.New)
	buf = slices.Concat(buf, h[:4])
	return base58.Bitcoin.Encode(buf)
}

// Address returns an address matching the provided out. Flags will be used for hints if multiple addresses are possible.
func (out *Out) Address(flags ...string) (string, error) {
	flags = append(flags, out.Flags...)
	net := ""
	if len(flags) > 0 {
		net = flags[0]
	}

	switch out.baseName() {
	case "eth", "evm":
		return eip55(out.raw), nil
	case "p2pkh", "p2pukh":
		// 0x76 0xa9 <pushdata> 0x88 0xac
		buf := out.raw
		buf = buf[2 : len(buf)-2]
		buf = parsePushBytes(buf)
		if buf == nil {
			return "", errors.New("invalid script for address type")
		}
		switch net {
		case "bitcoincash":
			// bitcoincash format
			return bech32m.CashAddrEncode("bitcoincash:", 0, buf)
		case "litecoin":
			return encodeBase58addr(0x30, buf), nil
		case "dogecoin":
			return encodeBase58addr(0x1e, buf), nil
		case "bitcoin":
			fallthrough
		default:
			// "good old" format
			return encodeBase58addr(0, buf), nil
		}
	case "p2sh":
		// 0xa9 <pushdata> 0x87
		buf := out.raw
		buf = buf[1 : len(buf)-1]
		buf = parsePushBytes(buf)
		if buf == nil {
			return "", errors.New("invalid script for address type")
		}
		switch net {
		case "bitcoincash":
			// bitcoincash format
			return bech32m.CashAddrEncode("bitcoincash:", 1, buf)
		case "litecoin":
			return encodeBase58addr(0x32, buf), nil
		case "dogecoin":
			return encodeBase58addr(0x16, buf), nil
		case "bitcoin":
			fallthrough
		default:
			// "good old" format
			return encodeBase58addr(0x05, buf), nil
		}
	case "p2wpkh", "p2wsh":
		// 0x00 <pushdata 20bytes>
		buf := parsePushBytes(out.raw[1:])
		switch net {
		case "litecoin":
			return bech32m.SegwitAddrEncode("ltc", 0, buf)
		case "bitcoin":
			return bech32m.SegwitAddrEncode("bc", 0, buf)
		}
	}

	return "", fmt.Errorf("could not transform outscript of format %s", out.Name)
}
