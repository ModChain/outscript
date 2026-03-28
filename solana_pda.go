package outscript

import (
	"crypto/sha256"
	"errors"

	"github.com/ModChain/edwards25519"
)

// SolanaCreateProgramAddress derives a program address from the given seeds and program ID.
// The resulting address must not lie on the Ed25519 curve, ensuring no private key exists for it.
// Each seed must be at most 32 bytes and at most 16 seeds are allowed.
func SolanaCreateProgramAddress(seeds [][]byte, programID SolanaKey) (SolanaKey, error) {
	if len(seeds) > 16 {
		return SolanaKey{}, errors.New("too many seeds: maximum 16")
	}
	h := sha256.New()
	for _, seed := range seeds {
		if len(seed) > 32 {
			return SolanaKey{}, errors.New("seed too long: maximum 32 bytes")
		}
		h.Write(seed)
	}
	h.Write(programID[:])
	h.Write([]byte("ProgramDerivedAddress"))

	hash := h.Sum(nil)

	// A valid PDA must NOT be on the Ed25519 curve.
	var buf [32]byte
	copy(buf[:], hash)
	var point edwards25519.ExtendedGroupElement
	if point.FromBytes(&buf) {
		return SolanaKey{}, errors.New("derived address is on the Ed25519 curve")
	}

	var result SolanaKey
	copy(result[:], hash)
	return result, nil
}

// SolanaFindProgramAddress finds a valid program address by iterating bump seeds
// from 255 down to 0, returning the first off-curve result along with its bump seed.
func SolanaFindProgramAddress(seeds [][]byte, programID SolanaKey) (SolanaKey, uint8, error) {
	for bump := uint8(255); ; bump-- {
		seedsWithBump := make([][]byte, len(seeds)+1)
		copy(seedsWithBump, seeds)
		seedsWithBump[len(seeds)] = []byte{bump}

		addr, err := SolanaCreateProgramAddress(seedsWithBump, programID)
		if err == nil {
			return addr, bump, nil
		}
		if bump == 0 {
			break
		}
	}
	return SolanaKey{}, 0, errors.New("could not find valid program address")
}
