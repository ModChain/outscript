package outscript

import (
	"crypto/sha256"
)

type Format []Insertable

var (
	Formats = map[string]Format{
		"p2pkh":  Format{Bytes{0x76, 0xa9}, IPushBytes{IHash160(IPubKeyComp)}, Bytes{0x88, 0xac}},
		"p2pukh": Format{Bytes{0x76, 0xa9}, IPushBytes{IHash160(IPubKey)}, Bytes{0x88, 0xac}},
		"p2pk":   Format{IPushBytes{IPubKeyComp}, Bytes{0xac}},
		"p2puk":  Format{IPushBytes{IPubKey}, Bytes{0xac}},
		"p2wpkh": Format{Bytes{0}, IPushBytes{IHash160(IPubKeyComp)}},
		// p2sh formats
		"p2sh:p2pkh":  Format{Bytes{0xa9}, IPushBytes{IHash160(Lookup("p2pkh"))}, Bytes{0x87}},
		"p2sh:p2pukh": Format{Bytes{0xa9}, IPushBytes{IHash160(Lookup("p2pukh"))}, Bytes{0x87}},
		"p2sh:p2pk":   Format{Bytes{0xa9}, IPushBytes{IHash160(Lookup("p2pk"))}, Bytes{0x87}},
		"p2sh:p2puk":  Format{Bytes{0xa9}, IPushBytes{IHash160(Lookup("p2puk"))}, Bytes{0x87}},
		"p2sh:p2wpkh": Format{Bytes{0xa9}, IPushBytes{IHash160(Lookup("p2wpkh"))}, Bytes{0x87}},
		// segwit formats
		"p2wsh:p2pkh":  Format{Bytes{0}, IPushBytes{IHash(Lookup("p2pkh"), sha256.New)}},
		"p2wsh:p2pukh": Format{Bytes{0}, IPushBytes{IHash(Lookup("p2pukh"), sha256.New)}},
		"p2wsh:p2pk":   Format{Bytes{0}, IPushBytes{IHash(Lookup("p2pk"), sha256.New)}},
		"p2wsh:p2puk":  Format{Bytes{0}, IPushBytes{IHash(Lookup("p2puk"), sha256.New)}},
		"p2wsh:p2wpkh": Format{Bytes{0}, IPushBytes{IHash(Lookup("p2wpkh"), sha256.New)}},
		// ethereum format
		"eth": Format{IHash(IPubKey, newEtherHash)},
	}
)