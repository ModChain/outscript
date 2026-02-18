package outscript

import (
	"encoding/hex"
	"fmt"

	"github.com/ModChain/base58"
)

// ParseSolanaAddress parses a Solana base58-encoded address and returns the
// corresponding [Out]. A valid Solana address is exactly 32 bytes when decoded.
func ParseSolanaAddress(address string) (*Out, error) {
	buf, err := base58.Bitcoin.Decode(address)
	if err != nil {
		return nil, fmt.Errorf("failed to decode solana address: %w", err)
	}
	if len(buf) != 32 {
		return nil, fmt.Errorf("invalid solana address: expected 32 bytes, got %d", len(buf))
	}
	return &Out{Name: "solana", Script: hex.EncodeToString(buf), raw: buf, Flags: []string{"solana"}}, nil
}
