package outscript_test

import (
	"math/big"
	"testing"

	"github.com/KarpelesLab/outscript"
)

func TestCumulativeDashReward(t *testing.T) {
	// Block 0 should give 5 DASH
	total, err := outscript.CumulativeReward("dash", 0)
	if err != nil {
		t.Fatalf("CumulativeReward(dash, 0) failed: %s", err)
	}
	expected := big.NewInt(5 * 100_000_000)
	if total.Cmp(expected) != 0 {
		t.Errorf("dash block 0: expected %s, got %s", expected, total)
	}

	// Block 1 should give 2 * 5 DASH
	total, err = outscript.CumulativeReward("dash", 1)
	if err != nil {
		t.Fatalf("CumulativeReward(dash, 1) failed: %s", err)
	}
	expected = big.NewInt(10 * 100_000_000)
	if total.Cmp(expected) != 0 {
		t.Errorf("dash block 1: expected %s, got %s", expected, total)
	}

	// Block 210240 (first block of second year) should include the full first year
	// plus one block of the second year
	total, err = outscript.CumulativeReward("dash", 210240)
	if err != nil {
		t.Fatalf("CumulativeReward(dash, 210240) failed: %s", err)
	}
	if total.Sign() <= 0 {
		t.Error("cumulative dash reward at block 210240 should be positive")
	}
}

func TestDashBlockReward(t *testing.T) {
	// Block 0: 5 DASH
	reward, err := outscript.BlockReward("dash", 0)
	if err != nil {
		t.Fatalf("BlockReward(dash, 0) failed: %s", err)
	}
	expected := big.NewInt(5 * 100_000_000)
	if reward.Cmp(expected) != 0 {
		t.Errorf("dash block 0 reward: expected %s, got %s", expected, reward)
	}

	// Block 210240: reduced by 13/14
	reward, err = outscript.BlockReward("dash", 210240)
	if err != nil {
		t.Fatalf("BlockReward(dash, 210240) failed: %s", err)
	}
	// 5 * 100000000 * 13 / 14 = 464285714 (floor)
	expected = big.NewInt(464285714)
	if reward.Cmp(expected) != 0 {
		t.Errorf("dash block 210240 reward: expected %s, got %s", expected, reward)
	}
}

func TestBlockRewardUnsupported(t *testing.T) {
	_, err := outscript.BlockReward("unsupported", 0)
	if err == nil {
		t.Error("expected error for unsupported network")
	}
}

func TestCumulativeRewardUnsupported(t *testing.T) {
	_, err := outscript.CumulativeReward("unsupported", 0)
	if err == nil {
		t.Error("expected error for unsupported network")
	}
}

func TestHalvingBlockRewardZero(t *testing.T) {
	// After many halvings the reward should be 0
	reward, err := outscript.BlockReward("bitcoin", 100*210000)
	if err != nil {
		t.Fatalf("BlockReward failed: %s", err)
	}
	if reward.Sign() != 0 {
		t.Errorf("expected 0 reward after many halvings, got %s", reward)
	}
}
