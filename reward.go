package outscript

import (
	"errors"
	"fmt"
	"math/big"
)

func BlockReward(network string, blockHeight uint64) (*big.Int, error) {
	reward := new(big.Int)

	switch network {
	// Bitcoin, Bitcoin Cash, Bitcoin Testnet share the same halving schedule:
	// - Initial reward: 50 BTC
	// - Halving interval: 210,000 blocks
	// - Reward is measured in satoshis (1 BTC = 100,000,000 satoshis)
	case "bitcoin", "bitcoin-cash", "bitcoin-testnet":
		halvingInterval := uint64(210000)
		baseReward := int64(50 * 100000000) // 50 BTC in satoshis
		halvingCount := blockHeight / halvingInterval

		// Technically, after ~32 halvings the reward becomes 0,
		// but you can simply shift until it goes to zero in practice.
		if halvingCount > 32 {
			reward.SetInt64(0)
		} else {
			// reward = baseReward >> halvingCount
			reward.SetInt64(baseReward >> halvingCount)
		}

	// Litecoin:
	// - Initial reward: 50 LTC
	// - Halving interval: 840,000 blocks
	// - Reward measured in litoshis (1 LTC = 100,000,000 litoshis)
	case "litecoin":
		halvingInterval := uint64(840000)
		baseReward := int64(50 * 100000000) // 50 LTC in litoshis
		halvingCount := blockHeight / halvingInterval
		if halvingCount > 32 {
			reward.SetInt64(0)
		} else {
			reward.SetInt64(baseReward >> halvingCount)
		}

	// Monacoin:
	// - Initial reward: 50 MONA
	// - Halving interval: 105,120 blocks (common setting)
	// - 1 MONA = 100,000,000 (like satoshis)
	case "monacoin":
		halvingInterval := uint64(105120)
		baseReward := int64(50 * 100000000) // 50 MONA in smallest units
		halvingCount := blockHeight / halvingInterval
		if halvingCount > 32 {
			reward.SetInt64(0)
		} else {
			reward.SetInt64(baseReward >> halvingCount)
		}

	// Dogecoin simplified schedule:
	// Historically started at 1,000,000 DOGE block reward, halving every 100k blocks.
	// After block 600,000 => 10,000 DOGE forever.
	// 1 DOGE = 100,000,000 in "shibes" (like satoshis).
	case "dogecoin":
		if blockHeight >= 600000 {
			reward.SetInt64(10000 * 100000000) // 10,000 DOGE
		} else {
			halvingInterval := uint64(100000)
			baseReward := int64(1000000 * 100000000) // 1,000,000 DOGE
			halvingCount := blockHeight / halvingInterval
			reward.SetInt64(baseReward >> halvingCount)
		}

	// Electraproto: Always returns zero
	case "electraproto":
		reward.SetInt64(0)

	default:
		return nil, errors.New("unsupported network: " + network)
	}

	return reward, nil
}

func main() {
	// Example usage:
	networks := []string{
		"bitcoin", "bitcoin-cash", "bitcoin-testnet",
		"litecoin", "monacoin", "dogecoin", "electraproto",
	}

	for _, net := range networks {
		r, err := BlockReward(net, 600000)
		if err != nil {
			fmt.Printf("Network: %s, Error: %s\n", net, err)
		} else {
			fmt.Printf("Network: %s, Block: %d, Reward: %s\n",
				net, 600000, r.String())
		}
	}
}
