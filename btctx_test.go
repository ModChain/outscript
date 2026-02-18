package outscript_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log"
	"strings"
	"testing"

	"github.com/KarpelesLab/outscript"
	"github.com/ModChain/secp256k1"
)

func TestBtcTxParse(t *testing.T) {
	txBin := must(hex.DecodeString("0100000003362c10b042d48378b428d60c5c98d8b8aca7a03e1a2ca1048bfd469934bbda95010000008b483045022046c8bc9fb0e063e2fc8c6b1084afe6370461c16cbf67987d97df87827917d42d022100c807fa0ab95945a6e74c59838cc5f9e850714d8850cec4db1e7f3bcf71d5f5ef0141044450af01b4cc0d45207bddfb47911744d01f768d23686e9ac784162a5b3a15bc01e6653310bdd695d8c35d22e9bb457563f8de116ecafea27a0ec831e4a3e9feffffffffc19529a54ae15c67526cc5e20e535973c2d56ef35ff51bace5444388331c4813000000008b48304502201738185959373f04cc73dbbb1d061623d51dc40aac0220df56dabb9b80b72f49022100a7f76bde06369917c214ee2179e583fefb63c95bf876eb54d05dfdf0721ed772014104e6aa2cf108e1c650e12d8dd7ec0a36e478dad5a5d180585d25c30eb7c88c3df0c6f5fd41b3e70b019b777abd02d319bf724de184001b3d014cb740cb83ed21a6ffffffffbaae89b5d2e3ca78fd3f13cf0058784e7c089fb56e1e596d70adcfa486603967010000008b483045022055efbaddb4c67c1f1a46464c8f770aab03d6b513779ad48735d16d4c5b9907c2022100f469d50a5e5556fc2c932645f6927ac416aa65bc83d58b888b82c3220e1f0b73014104194b3f8aa08b96cae19b14bd6c32a92364bea3051cb9f018b03e3f09a57208ff058f4b41ebf96b9911066aef3be22391ac59175257af0984d1432acb8f2aefcaffffffff0340420f00000000001976a914c0fbb13eb10b57daa78b47660a4ffb79c29e2e6b88ac204e0000000000001976a9142cae94ffdc05f8214ccb2b697861c9c07e3948ee88ac1c2e0100000000001976a9146e03561cd4d6033456cc9036d409d2bf82721e9888ac00000000"))

	tx := &outscript.BtcTx{}
	_, err := tx.ReadFrom(bytes.NewReader(txBin))
	if err != nil {
		t.Errorf("failed to parse tx: %s", err)
	}
	//log.Printf("tx = %+v", tx)

	if hex.EncodeToString(must(tx.Hash())) != "38d4cfeb57d6685753b7a3b3534c3cb576c34ca7344cd4582f9613ebf0c2b02a" {
		t.Errorf("unexpected txid value for test tx")
	}
}

func TestBtcTxParseWitness(t *testing.T) {
	txBin := must(hex.DecodeString("0100000000010213206299feb17742091c3cb2ab45faa3aa87922d3c030cafb3f798850a2722bf0000000000feffffffa12f2424b9599898a1d30f06e1ce55eba7fabfeee82ae9356f07375806632ff3010000006b483045022100fcc8cf3014248e1a0d6dcddf03e80f7e591605ad0dbace27d2c0d87274f8cd66022053fcfff64f35f22a14deb657ac57f110084fb07bb917c3b42e7d033c54c7717b012102b9e4dcc33c9cc9cb5f42b96dddb3b475b067f3e21125f79e10c853e5ca8fba31feffffff02206f9800000000001976a9144841b9874d913c430048c78a7b18baebdbea440588ac8096980000000000160014e4873ef43eac347471dd94bc899c51b395a509a502483045022100dd8250f8b5c2035d8feefae530b10862a63030590a851183cb61b3672eb4f26e022057fe7bc8593f05416c185d829b574290fb8706423451ebd0a0ae50c276b87b43012102179862f40b85fa43487500f1d6b13c864b5eb0a83999738db0f7a6b91b2ec64f00db080000"))

	tx := &outscript.BtcTx{}
	_, err := tx.ReadFrom(bytes.NewReader(txBin))
	if err != nil {
		t.Errorf("failed to parse tx: %s", err)
	}
	//log.Printf("tx = %+v", tx)

	if hex.EncodeToString(must(tx.Hash())) != "99e7484eafb6e01622c395c8cae7cb9f8822aab6ba993696b39df8b60b0f4b11" {
		t.Errorf("unexpected txid value for test tx")
	}
}

func TestBtxTxP2WPKH(t *testing.T) {
	// test vector from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
	// this is nice because it includes both a standard p2pk input and a segwit p2wpkh input
	key0 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866")))
	key1 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")))

	s0, _ := outscript.New(key0.PubKey()).Generate("p2pk")
	if hex.EncodeToString(s0) != "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac" {
		t.Errorf("bad script output for private key to p2pk script")
	}
	s1, _ := outscript.New(key1.PubKey()).Generate("p2wpkh")
	if hex.EncodeToString(s1) != "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1" {
		t.Errorf("bad script output for private key to p2pk script")
	}

	txHex := strings.Join([]string{
		"01000000", // version
		"02",       // num txIn
		"fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", "00000000", "00", "eeffffff", // txIn
		"ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", "01000000", "00", "ffffffff", // txIn
		"02",                                                                               // num txOut
		"202cb20600000000", "1976a914", "8280b37df378db99f66f85c95a783a76ac7a6d59", "88ac", // txOut
		"9093510d00000000", "1976a914", "3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159", "88ac", // txOut
		"11000000", // nLockTime
	}, "")

	tx := &outscript.BtcTx{}
	_, err := tx.ReadFrom(bytes.NewReader(must(hex.DecodeString(txHex))))
	if err != nil {
		t.Errorf("failed to parse tx: %s", err)
	}

	err = tx.Sign(&outscript.BtcTxSign{Key: key0, Scheme: "p2pk"}, &outscript.BtcTxSign{Key: key1, Scheme: "p2wpkh", Amount: 600000000})
	if err != nil {
		t.Errorf("failed to sign transaction: %s", err)
	}
	if hex.EncodeToString(tx.In[0].Script) != "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01" {
		//log.Printf("tx.In[0].Script = %x", tx.In[0].Script)
		t.Errorf("invalid signature value for input[0] scheme=p2pk")
	}
	if hex.EncodeToString(tx.In[1].Witnesses[0]) != "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01" {
		//log.Printf("tx.in[1].Witnesses = %x", tx.In[1].Witnesses)
		t.Errorf("invalid signature value for input[1] scheme=p2wpkh")
	}

	signedTxHex := strings.Join([]string{
		"01000000", // version
		"00",       // marker
		"01",       // flag
		"02",       // num txIn
		"fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", "00000000",
		"494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01",
		"eeffffff", // txIn
		"ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", "01000000", "00", "ffffffff", // txIn
		"02",                                                                               // num txOut
		"202cb20600000000", "1976a914", "8280b37df378db99f66f85c95a783a76ac7a6d59", "88ac", // txOut
		"9093510d00000000", "1976a914", "3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159", "88ac", // txOut
		"00", // witness (empty)
		"02", // witness (2 pushes)
		"47", // push length
		"304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01", // push
		"21", // push length
		"025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357", // push
		"11000000", // nLockTime
	}, "")

	if hex.EncodeToString(tx.Bytes()) != signedTxHex {
		//log.Printf("signed tx = %x", tx.Bytes())
		t.Errorf("invalid serialized transaction for signed tx")
	}
}

func TestBtxTxP2SHP2WPKH(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")))

	txHex := "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
	tx := &outscript.BtcTx{}
	_, err := tx.ReadFrom(bytes.NewReader(must(hex.DecodeString(txHex))))
	if err != nil {
		t.Errorf("failed to parse tx: %s", err)
	}

	err = tx.Sign(&outscript.BtcTxSign{Key: key, Scheme: "p2sh:p2wpkh", Amount: 1000000000})
	if err != nil {
		t.Errorf("failed to sign P2SH-P2WPKH transaction: %s", err)
	}

	signedTxHex := "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
	if hex.EncodeToString(tx.Bytes()) != signedTxHex {
		log.Printf("signed tx = %x", tx.Bytes())
		t.Errorf("invalid serialized transaction for signed P2SH-P2WPKH tx")
	}
}

func TestBtxTxP2WSH(t *testing.T) {
	// Uses the same BIP-143 transaction and keys as TestBtxTxP2WPKH but signs
	// input 1 with p2wsh:p2pkh instead of p2wpkh. The BIP-143 preimage for
	// p2wsh:p2pkh uses the same scriptCode as p2wpkh (the p2pkh script), so
	// the signature must be identical.
	key0 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866")))
	key1 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")))

	txHex := strings.Join([]string{
		"01000000", // version
		"02",       // num txIn
		"fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", "00000000", "00", "eeffffff", // txIn
		"ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", "01000000", "00", "ffffffff", // txIn
		"02",                                                                               // num txOut
		"202cb20600000000", "1976a914", "8280b37df378db99f66f85c95a783a76ac7a6d59", "88ac", // txOut
		"9093510d00000000", "1976a914", "3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159", "88ac", // txOut
		"11000000", // nLockTime
	}, "")

	tx := &outscript.BtcTx{}
	_, err := tx.ReadFrom(bytes.NewReader(must(hex.DecodeString(txHex))))
	if err != nil {
		t.Fatalf("failed to parse tx: %s", err)
	}

	err = tx.Sign(&outscript.BtcTxSign{Key: key0, Scheme: "p2pk"}, &outscript.BtcTxSign{Key: key1, Scheme: "p2wsh:p2pkh", Amount: 600000000})
	if err != nil {
		t.Fatalf("failed to sign p2wsh:p2pkh transaction: %s", err)
	}

	// signature must match the p2wpkh signature from BIP-143 (same preimage)
	expectedSig := "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
	if hex.EncodeToString(tx.In[1].Witnesses[0]) != expectedSig {
		t.Errorf("invalid signature for p2wsh:p2pkh, got %x", tx.In[1].Witnesses[0])
	}

	// witness must have 3 items: [sig, pubkey, witnessScript]
	if len(tx.In[1].Witnesses) != 3 {
		t.Fatalf("expected 3 witness items, got %d", len(tx.In[1].Witnesses))
	}

	// verify compressed pubkey
	if hex.EncodeToString(tx.In[1].Witnesses[1]) != "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357" {
		t.Errorf("invalid pubkey in witness, got %x", tx.In[1].Witnesses[1])
	}

	// verify witness script is the p2pkh script for this key
	if hex.EncodeToString(tx.In[1].Witnesses[2]) != "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac" {
		t.Errorf("invalid witness script, got %x", tx.In[1].Witnesses[2])
	}

	// input script must be nil for native segwit
	if tx.In[1].Script != nil {
		t.Errorf("expected nil script for p2wsh input, got %x", tx.In[1].Script)
	}
}

func TestBtxTxP2WSHP2PK(t *testing.T) {
	// Test p2wsh:p2pk signing — witness should be [sig, witnessScript] (2 items)
	key0 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866")))
	key1 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")))

	txHex := strings.Join([]string{
		"01000000",
		"02",
		"fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", "00000000", "00", "eeffffff",
		"ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", "01000000", "00", "ffffffff",
		"02",
		"202cb20600000000", "1976a914", "8280b37df378db99f66f85c95a783a76ac7a6d59", "88ac",
		"9093510d00000000", "1976a914", "3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159", "88ac",
		"11000000",
	}, "")

	tx := &outscript.BtcTx{}
	_, err := tx.ReadFrom(bytes.NewReader(must(hex.DecodeString(txHex))))
	if err != nil {
		t.Fatalf("failed to parse tx: %s", err)
	}

	err = tx.Sign(&outscript.BtcTxSign{Key: key0, Scheme: "p2pk"}, &outscript.BtcTxSign{Key: key1, Scheme: "p2wsh:p2pk", Amount: 600000000})
	if err != nil {
		t.Fatalf("failed to sign p2wsh:p2pk transaction: %s", err)
	}

	// witness must have 2 items: [sig, witnessScript]
	if len(tx.In[1].Witnesses) != 2 {
		t.Fatalf("expected 2 witness items for p2wsh:p2pk, got %d", len(tx.In[1].Witnesses))
	}

	// witness script must be the p2pk script (compressed pubkey + OP_CHECKSIG)
	expectedWS := must(outscript.New(key1.PubKey()).Generate("p2pk"))
	if hex.EncodeToString(tx.In[1].Witnesses[1]) != hex.EncodeToString(expectedWS) {
		t.Errorf("invalid witness script for p2wsh:p2pk, got %x", tx.In[1].Witnesses[1])
	}

	if tx.In[1].Script != nil {
		t.Errorf("expected nil script for p2wsh input, got %x", tx.In[1].Script)
	}
}

func TestBtxTxP2WSHAutoDetect(t *testing.T) {
	// Test auto-detection: scheme "p2wsh" with the input's Script pre-populated
	// with the p2wsh scriptPubKey (OP_0 <SHA256(witnessScript)>).
	key0 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866")))
	key1 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")))

	txHex := strings.Join([]string{
		"01000000",
		"02",
		"fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", "00000000", "00", "eeffffff",
		"ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", "01000000", "00", "ffffffff",
		"02",
		"202cb20600000000", "1976a914", "8280b37df378db99f66f85c95a783a76ac7a6d59", "88ac",
		"9093510d00000000", "1976a914", "3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159", "88ac",
		"11000000",
	}, "")

	tx := &outscript.BtcTx{}
	_, err := tx.ReadFrom(bytes.NewReader(must(hex.DecodeString(txHex))))
	if err != nil {
		t.Fatalf("failed to parse tx: %s", err)
	}

	// Pre-populate input 1 with the p2wsh:p2pkh scriptPubKey so auto-detection works
	p2wshScript := must(outscript.New(key1.PubKey()).Generate("p2wsh:p2pkh"))
	tx.In[1].Script = p2wshScript

	err = tx.Sign(&outscript.BtcTxSign{Key: key0, Scheme: "p2pk"}, &outscript.BtcTxSign{Key: key1, Scheme: "p2wsh", Amount: 600000000})
	if err != nil {
		t.Fatalf("failed to sign auto-detected p2wsh transaction: %s", err)
	}

	// should produce the same signature as explicit p2wsh:p2pkh
	expectedSig := "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
	if hex.EncodeToString(tx.In[1].Witnesses[0]) != expectedSig {
		t.Errorf("auto-detected p2wsh signature mismatch, got %x", tx.In[1].Witnesses[0])
	}

	if len(tx.In[1].Witnesses) != 3 {
		t.Fatalf("expected 3 witness items, got %d", len(tx.In[1].Witnesses))
	}

	// input script must be cleared to nil after signing
	if tx.In[1].Script != nil {
		t.Errorf("expected nil script after signing, got %x", tx.In[1].Script)
	}
}

func TestBtxTxP2WSHAutoDetectDefault(t *testing.T) {
	// Test auto-detection fallback: scheme "p2wsh" with empty input Script
	// should default to p2pkh (most common single-key case).
	key0 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866")))
	key1 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")))

	txHex := strings.Join([]string{
		"01000000",
		"02",
		"fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", "00000000", "00", "eeffffff",
		"ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", "01000000", "00", "ffffffff",
		"02",
		"202cb20600000000", "1976a914", "8280b37df378db99f66f85c95a783a76ac7a6d59", "88ac",
		"9093510d00000000", "1976a914", "3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159", "88ac",
		"11000000",
	}, "")

	tx := &outscript.BtcTx{}
	_, err := tx.ReadFrom(bytes.NewReader(must(hex.DecodeString(txHex))))
	if err != nil {
		t.Fatalf("failed to parse tx: %s", err)
	}

	// input Script is empty — should default to p2pkh
	err = tx.Sign(&outscript.BtcTxSign{Key: key0, Scheme: "p2pk"}, &outscript.BtcTxSign{Key: key1, Scheme: "p2wsh", Amount: 600000000})
	if err != nil {
		t.Fatalf("failed to sign default p2wsh transaction: %s", err)
	}

	// same result as explicit p2wsh:p2pkh
	expectedSig := "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
	if hex.EncodeToString(tx.In[1].Witnesses[0]) != expectedSig {
		t.Errorf("default p2wsh signature mismatch, got %x", tx.In[1].Witnesses[0])
	}

	if len(tx.In[1].Witnesses) != 3 {
		t.Fatalf("expected 3 witness items, got %d", len(tx.In[1].Witnesses))
	}

	// verify witness script is p2pkh
	if hex.EncodeToString(tx.In[1].Witnesses[2]) != "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac" {
		t.Errorf("expected p2pkh witness script, got %x", tx.In[1].Witnesses[2])
	}
}

func TestBtxTxP2WSHAutoDetectP2PK(t *testing.T) {
	// Test auto-detection with a p2wsh:p2pk scriptPubKey in the input.
	key0 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866")))
	key1 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")))

	txHex := strings.Join([]string{
		"01000000",
		"02",
		"fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", "00000000", "00", "eeffffff",
		"ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", "01000000", "00", "ffffffff",
		"02",
		"202cb20600000000", "1976a914", "8280b37df378db99f66f85c95a783a76ac7a6d59", "88ac",
		"9093510d00000000", "1976a914", "3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159", "88ac",
		"11000000",
	}, "")

	tx := &outscript.BtcTx{}
	_, err := tx.ReadFrom(bytes.NewReader(must(hex.DecodeString(txHex))))
	if err != nil {
		t.Fatalf("failed to parse tx: %s", err)
	}

	// Pre-populate with p2wsh:p2pk scriptPubKey
	p2wshScript := must(outscript.New(key1.PubKey()).Generate("p2wsh:p2pk"))
	tx.In[1].Script = p2wshScript

	err = tx.Sign(&outscript.BtcTxSign{Key: key0, Scheme: "p2pk"}, &outscript.BtcTxSign{Key: key1, Scheme: "p2wsh", Amount: 600000000})
	if err != nil {
		t.Fatalf("failed to sign auto-detected p2wsh:p2pk transaction: %s", err)
	}

	// witness must have 2 items: [sig, witnessScript] — detected p2pk
	if len(tx.In[1].Witnesses) != 2 {
		t.Fatalf("expected 2 witness items for auto-detected p2pk, got %d", len(tx.In[1].Witnesses))
	}

	// witness script must be the p2pk script
	expectedWS := must(outscript.New(key1.PubKey()).Generate("p2pk"))
	if hex.EncodeToString(tx.In[1].Witnesses[1]) != hex.EncodeToString(expectedWS) {
		t.Errorf("auto-detected witness script mismatch, got %x", tx.In[1].Witnesses[1])
	}
}

func TestBtxTxP2WSHPrefill(t *testing.T) {
	in := &outscript.BtcTxInput{}

	schemes := []struct {
		name         string
		witnessCount int
	}{
		{"p2wsh:p2pk", 2},   // [sig, witnessScript]
		{"p2wsh:p2puk", 2},  // [sig, witnessScript]
		{"p2wsh:p2pkh", 3},  // [sig, pubkey, witnessScript]
		{"p2wsh:p2pukh", 3}, // [sig, pubkey, witnessScript]
	}

	for _, s := range schemes {
		err := in.Prefill(s.name)
		if err != nil {
			t.Errorf("Prefill(%s) failed: %s", s.name, err)
			continue
		}
		if in.Script != nil {
			t.Errorf("Prefill(%s): expected nil script, got %x", s.name, in.Script)
		}
		if len(in.Witnesses) != s.witnessCount {
			t.Errorf("Prefill(%s): expected %d witness items, got %d", s.name, s.witnessCount, len(in.Witnesses))
		}
	}
}

func TestBtxTxP2WSHPrefillBare(t *testing.T) {
	// Bare "p2wsh" scheme must be accepted by Prefill and produce the same
	// witness layout as "p2wsh:p2pkh" (the default inner type).
	in := &outscript.BtcTxInput{}
	err := in.Prefill("p2wsh")
	if err != nil {
		t.Fatalf("Prefill(p2wsh) failed: %s", err)
	}
	if in.Script != nil {
		t.Errorf("expected nil script after Prefill(p2wsh), got %x", in.Script)
	}
	// p2wsh defaults to p2pkh inner → [sig, pubkey, witnessScript]
	if len(in.Witnesses) != 3 {
		t.Errorf("expected 3 witness items for Prefill(p2wsh), got %d", len(in.Witnesses))
	}
}

func TestBtxTxP2WSHComputeSize(t *testing.T) {
	// Verify that ComputeSize after Prefill produces a value >= ComputeSize
	// after actual signing, for all p2wsh schemes. This is the bug that caused
	// "min relay fee not met" errors.
	key0 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866")))
	key1 := secp256k1.PrivKeyFromBytes(must(hex.DecodeString("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")))

	baseTxHex := strings.Join([]string{
		"01000000",
		"02",
		"fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", "00000000", "00", "eeffffff",
		"ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", "01000000", "00", "ffffffff",
		"02",
		"202cb20600000000", "1976a914", "8280b37df378db99f66f85c95a783a76ac7a6d59", "88ac",
		"9093510d00000000", "1976a914", "3bde42dbee7e4dbe6a21b2d50ce2f0167faa8159", "88ac",
		"11000000",
	}, "")

	schemes := []string{"p2wsh", "p2wsh:p2pk", "p2wsh:p2pkh", "p2wsh:p2puk", "p2wsh:p2pukh"}

	for _, scheme := range schemes {
		// Build and prefill to get estimated size
		txEst := &outscript.BtcTx{}
		_, err := txEst.ReadFrom(bytes.NewReader(must(hex.DecodeString(baseTxHex))))
		if err != nil {
			t.Fatalf("failed to parse tx: %s", err)
		}
		err = txEst.In[0].Prefill("p2pk")
		if err != nil {
			t.Fatalf("Prefill(p2pk) failed: %s", err)
		}
		err = txEst.In[1].Prefill(scheme)
		if err != nil {
			t.Fatalf("Prefill(%s) failed: %s", scheme, err)
		}
		estimatedSize := txEst.ComputeSize()

		// Build and sign to get actual size
		txSig := &outscript.BtcTx{}
		_, err = txSig.ReadFrom(bytes.NewReader(must(hex.DecodeString(baseTxHex))))
		if err != nil {
			t.Fatalf("failed to parse tx: %s", err)
		}

		signScheme := scheme
		if signScheme == "p2wsh" {
			signScheme = "p2wsh:p2pkh" // default inner for bare p2wsh
		}
		err = txSig.Sign(&outscript.BtcTxSign{Key: key0, Scheme: "p2pk"}, &outscript.BtcTxSign{Key: key1, Scheme: signScheme, Amount: 600000000})
		if err != nil {
			t.Fatalf("Sign with scheme %s failed: %s", signScheme, err)
		}
		actualSize := txSig.ComputeSize()

		if estimatedSize < actualSize {
			t.Errorf("ComputeSize after Prefill(%s) = %d, but after signing = %d (estimate too low by %d vbytes)",
				scheme, estimatedSize, actualSize, actualSize-estimatedSize)
		}
	}
}

func TestBtcAmount(t *testing.T) {
	v := &outscript.BtcTxOutput{Amount: 123456700}

	buf, err := json.Marshal(v)
	if err != nil {
		t.Errorf("failed to marshal: %s", err)
		return
	}
	if !strings.HasPrefix(string(buf), `{"value":1.23456700,`) {
		t.Errorf("invalid formatting for our value: %s", buf)
	}

	v = nil
	err = json.Unmarshal([]byte(`{"value":"2.424242"}`), &v)
	if err != nil {
		t.Errorf("failed to unmarshal: %s", err)
		return
	}
	if v.Amount != 242424200 {
		t.Errorf("invalid amount in unmarshal of value, got %d", v.Amount)
	}

	vals := []outscript.BtcAmount{123, 123000, 123456789654}
	for _, vt := range vals {
		buf, err := json.Marshal(vt)
		if err != nil {
			t.Errorf("failed to marshal %d: %s", vt, err)
			continue
		}
		var v3 outscript.BtcAmount
		err = json.Unmarshal(buf, &v3)
		if err != nil {
			t.Errorf("failed to unmarshal %s: %s", buf, err)
			continue
		}
		if v3 != vt {
			t.Errorf("failed to get back to initial value: %d != %d", vt, v3)
		}
	}
}
