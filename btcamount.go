package outscript

import (
	"errors"
	"strconv"
	"strings"
)

type BtcAmount uint64

func (b BtcAmount) MarshalJSON() ([]byte, error) {
	// return amount as a float, always 8 decimals
	s := strconv.FormatUint(uint64(b), 10)
	ln := len(s)
	if ln <= 8 {
		// add zeroes
		s = strings.Repeat("0", 9-ln) + s
		ln = 9
	}
	// we now know that len(s) >= 9, cut it so we add a zero
	s = s[:ln-8] + "." + s[ln-8:]
	return []byte(s), nil
}

func (ba *BtcAmount) UnmarshalJSON(b []byte) error {
	// locate dot position
	if string(b) == "null" {
		return nil
	}
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		b = b[1 : len(b)-1]
	}

	return ba.UnmarshalText(b)
}

func (ba *BtcAmount) UnmarshalText(b []byte) error {
	s := string(b)

	if strings.HasPrefix(s, "0x") {
		// if hex value, handle it has integer
		v, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return err
		}
		*ba = BtcAmount(v)
		return nil
	}

	pos := strings.IndexByte(s, '.')
	if pos == -1 {
		// no dot means this is an int, multiply it by 100000000
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return err
		}
		v = v * 1_0000_0000
		*ba = BtcAmount(v)
		return nil
	}
	// we have a ., it should be at len(s)-8 ideally, but let's be flexible
	// we will not allow more than 8 decimals however
	ln := len(s)
	decCount := ln - pos - 1
	if decCount > 8 {
		return errors.New("cannot parse amount with more than 8 decimals")
	}
	s = s[:pos] + s[pos+1:] // without the dot
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	for decCount < 8 {
		// multiply by 10 until decCount==8
		decCount += 1
		v *= 10
	}
	*ba = BtcAmount(v)
	return nil
}
