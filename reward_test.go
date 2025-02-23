package outscript_test

import (
	"math/big"
	"testing"

	"github.com/ModChain/outscript"
)

// TestBlockReward checks the single-block reward at selected heights.
func TestBlockReward(t *testing.T) {
	// We'll define test cases with:
	//  - network name
	//  - block height
	//  - expected block reward (as a *big.Int)
	// For big.Int constants, we use big.NewInt(...) or we can define them once and reuse.

	// For example, 50 BTC in satoshis = 50 * 100000000 = 5,000,000,000
	fiftyBTC := big.NewInt(50 * 100000000)
	twentyFiveBTC := big.NewInt(25 * 100000000)

	tests := []struct {
		name    string
		network string
		height  uint64
		want    *big.Int
	}{
		// Bitcoin halving examples:
		{
			name:    "Bitcoin block 0 => 50 BTC",
			network: "bitcoin",
			height:  0,
			want:    fiftyBTC,
		},
		{
			name:    "Bitcoin block 209,999 => still 50 BTC",
			network: "bitcoin",
			height:  209_999,
			want:    fiftyBTC,
		},
		{
			name:    "Bitcoin block 210,000 => 25 BTC",
			network: "bitcoin",
			height:  210_000,
			want:    twentyFiveBTC,
		},

		// Litecoin, just a simple sanity check at block 0:
		{
			name:    "Litecoin block 0 => 50 LTC in litoshis",
			network: "litecoin",
			height:  0,
			want:    big.NewInt(50 * 100000000),
		},

		// Dogecoin:
		{
			name:    "Doge block 0 => 1,000,000 DOGE",
			network: "dogecoin",
			height:  0,
			// 1,000,000 DOGE => 1,000,000 * 100,000,000 = 100,000,000,000,000
			want: big.NewInt(1_000_000 * 100_000_000),
		},
		{
			name:    "Doge block 600,000 => 10,000 DOGE",
			network: "dogecoin",
			height:  600_000,
			// 10,000 DOGE in shibes:
			want: big.NewInt(10_000 * 100_000_000),
		},

		// Dash:
		{
			name:    "Dash block 0 => 5 DASH",
			network: "dash",
			height:  0,
			// 5 * 100,000,000 = 500,000,000 duffs
			want: big.NewInt(5 * 100_000_000),
		},
		{
			name:    "Dash block 210,240 => first yearly drop (≈ 4.64285714... DASH)",
			network: "dash",
			height:  210_240,
			// mathematically: floor( 5e8 * (13/14)^1 ) = floor( 500000000 * 0.9285714... ) = 464285714
			want: big.NewInt(464285714),
		},

		// Electraproto => always 0
		{
			name:    "Electraproto block 100 => always 0",
			network: "electraproto",
			height:  100,
			want:    big.NewInt(0),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := outscript.BlockReward(tc.network, tc.height)
			if err != nil {
				t.Fatalf("BlockReward returned error: %v", err)
			}
			if got.Cmp(tc.want) != 0 {
				t.Errorf("BlockReward mismatch for %q (block %d): got %s, want %s",
					tc.network, tc.height, got.String(), tc.want.String())
			}
		})
	}
}

// TestCumulativeReward checks total issued coins up to a given block.
func TestCumulativeReward(t *testing.T) {
	tests := []struct {
		name    string
		network string
		height  uint64
		want    *big.Int
	}{
		// Bitcoin:
		{
			name:    "Bitcoin block 0 => 50 BTC total",
			network: "bitcoin",
			height:  0,
			// block 0 => 1 block => 50 BTC => 5,000,000,000 sat
			want: big.NewInt(50 * 100000000),
		},
		{
			name:    "Bitcoin block 1 => 100 BTC total",
			network: "bitcoin",
			height:  1,
			// blocks 0 + 1 => 2 blocks => 2*50 BTC => 100 BTC = 10,000,000,000 sat
			want: big.NewInt(100 * 100000000),
		},
		{
			name:    "Bitcoin block 209,999 => 50 BTC each block (210000 blocks)",
			network: "bitcoin",
			height:  209_999,
			// 210,000 blocks * 50 BTC => 10,500,000 BTC
			// In sat: 10,500,000 * 100,000,000 = 1,050,000,000,000,000
			want: big.NewInt(0).Mul(big.NewInt(10_500_000), big.NewInt(100_000_000)),
		},
		{
			name:    "Bitcoin block 210,000 => plus one block of 25 BTC => 210,001 blocks in total",
			network: "bitcoin",
			height:  210_000,
			// total from 0..209,999 => (210,000 blocks * 50 BTC) = 10,500,000 BTC
			// plus block 210,000 => 25 BTC => total 10,500,025 BTC
			// in sat: 10,500,025 * 100,000,000 = 1,050,002,500,000,000
			want: big.NewInt(0).Mul(big.NewInt(10_500_025), big.NewInt(100_000_000)),
		},

		// Dogecoin:
		{
			name:    "Dogecoin block 0 => total 1,000,000 DOGE",
			network: "dogecoin",
			height:  0,
			want:    big.NewInt(1_000_000 * 100_000_000),
		},
		{
			name:    "Dogecoin block 1 => total 2,000,000 DOGE",
			network: "dogecoin",
			height:  1,
			// block0 => 1,000,000 DOGE, block1 => 1,000,000 DOGE => total 2,000,000 DOGE
			want: big.NewInt(2_000_000 * 100_000_000),
		},
		{
			name:    "Dogecoin block 100,000 => entire first halving interval + partial checks",
			network: "dogecoin",
			height:  100_000,
			// We'll trust the function's logic. If you need an exact known number, you can do:
			//   - blocks [0..99,999] => each 1,000,000 DOGE => 100,000 * 1,000,000 = 100 billion DOGE
			//   - block #100,000 => now 500,000 DOGE
			// So total => 100,000 * 1,000,000 + 500,000 = 100,000,500,000 DOGE
			// In shibes => 100,000,500,000 * 100,000,000 = 1e7 * 1,000,005,000,000? Let's do carefully:
			// 100,000 * 1,000,000 = 100,000,000,000 DOGE from the first interval (blocks 0..99,999)
			// plus block #100,000 => 500,000 DOGE => total 100,000,500,000 DOGE
			// in shibes => 100,000,500,000 * 100,000,000 = 10,000,050,000,000,000,000
			want: func() *big.Int {
				doge := big.NewInt(100_000_500_000)
				shibesFactor := big.NewInt(100_000_000)
				return doge.Mul(doge, shibesFactor)
			}(),
		},
		{
			name:    "Dogecoin block 600,000 => includes final halving plus new 10,000 reward blocks",
			network: "dogecoin",
			height:  600_000,
			// This is a big number; in production you might store it in a comment or compare to a reference chain data.
			// We trust the function for now. If you have a known reference, you can place it here.
			// For demonstration, let's just check that it runs. We'll put a plausible known sum:
			want: func() *big.Int {
				// Summation of intervals:
				//   i=0: blocks 0..99,999 => 1,000,000 DOGE each => 100,000 * 1,000,000 = 100,000,000,000 DOGE
				//   i=1: blocks 100,000..199,999 => 500,000 DOGE => another 100,000 * 500,000 = 50,000,000,000 DOGE
				//   i=2: blocks 200,000..299,999 => 250,000 DOGE => 100,000 * 250,000 = 25,000,000,000 DOGE
				//   i=3: 300,000..399,999 => 125,000 DOGE => 100,000 * 125,000 = 12,500,000,000
				//   i=4: 400,000..499,999 => 62,500 DOGE => 100,000 * 62,500 = 6,250,000,000
				//   i=5: 500,000..599,999 => 31,250 DOGE => 100,000 * 31,250 = 3,125,000,000
				// total from these 6 intervals = 196,875,000,000 DOGE
				//
				// block 600,000 => reward = 10,000 DOGE => so total is 196,875,010,000 DOGE
				// in shibes => multiply by 100,000,000
				doge := big.NewInt(196_875_010_000)
				return doge.Mul(doge, big.NewInt(100_000_000))
			}(),
		},

		// Electraproto => always 0
		{
			name:    "Electraproto block 999 => total 0",
			network: "electraproto",
			height:  999,
			want:    big.NewInt(0),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := outscript.CumulativeReward(tc.network, tc.height)
			if err != nil {
				t.Fatalf("CumulativeReward returned error: %v", err)
			}
			if got.Cmp(tc.want) != 0 {
				t.Errorf("CumulativeReward mismatch for %q (block %d): got %s, want %s",
					tc.network, tc.height, got.String(), tc.want.String())
			}
		})
	}
}
