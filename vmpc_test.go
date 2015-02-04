package vmpc

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

// key and iv for testing, as specified on http://www.vmpcfunction.com/cipher.htm
var k []byte = []byte{0x96, 0x61, 0x41, 0x0A, 0xB7, 0x97, 0xD8, 0xA9, 0xEB, 0x76, 0x7C, 0x21, 0x17, 0x2D, 0xF6, 0xC7}
var iv []byte = []byte{0x4B, 0x5C, 0x2F, 0x00, 0x3E, 0x67, 0xF3, 0x95, 0x57, 0xA8, 0xD2, 0x6F, 0x3D, 0xA2, 0xB1, 0x55}

type teststru struct {
	idx uint32
	val byte
}

var testtable3 []teststru = []teststru{
	{0, 0xb6},
	{1, 0xeb},
	{2, 0xae},
	{3, 0xfe},

	{252, 0x48},
	{253, 0x17},
	{254, 0x24},
	{255, 0x73},

	{1020, 0x1d},
	{1021, 0xae},
	{1022, 0xc3},
	{1023, 0x5a},

	{102396, 0x1d},
	{102397, 0xa7},
	{102398, 0xe1},
	{102399, 0xdc},
}

var testtable []teststru = []teststru{
	{0, 0xa8},
	{1, 0x24},
	{2, 0x79},
	{3, 0xf5},

	{252, 0xb8},
	{253, 0xfc},
	{254, 0x66},
	{255, 0xa4},

	{1020, 0xe0},
	{1021, 0x56},
	{1022, 0x40},
	{1023, 0xa5},

	{102396, 0x81},
	{102397, 0xca},
	{102398, 0x49},
	{102399, 0x9a},
}

func TestCipher3(t *testing.T) {
	c, err := NewCipher3(k, iv)
	if err != nil {
		t.Fatalf("err: %s\n", err)
	}
	b := make([]byte, 102400)
	c.XORKeyStream(b, b)

	n := len(testtable3)
	for idx, tv := range testtable3 {
		if b[tv.idx] != tv.val {
			t.Fatalf("bad: %d . wanted 0x%02x ; got %02x\n", tv.idx, tv.val, b[tv.idx])
		} else {
			t.Logf("%4d/%3d : OK\n", idx, n)
		}
	}
}

func TestCipher(t *testing.T) {
	c, err := NewCipher(k, iv)
	if err != nil {
		t.Fatalf("err: %s\n", err)
	}
	b := make([]byte, 102400)
	c.XORKeyStream(b, b)

	n := len(testtable)
	for idx, tv := range testtable {
		if b[tv.idx] != tv.val {
			t.Fatalf("bad: %d . wanted 0x%02x ; got %02x\n", tv.idx, tv.val, b[tv.idx])
		} else {
			t.Logf("%4d/%3d : OK\n", idx, n)
		}
	}
}

type cantReadRandErr struct {
	wanted, got int
}

func (e cantReadRandErr) Error() string {
	return fmt.Sprintf("err reading %d random bytes; got only %d", e.wanted, e.got)
}

func get_rand(cnt int, t *testing.T) []byte {
	b := make([]byte, cnt)
	n, err := rand.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != cnt {
		t.Fatal(cantReadRandErr{cnt, n})
	}
	return b
}

func cryptwith(key, iv, buff []byte, t *testing.T, ksa3 bool) []byte {
	var v *Cipher
	var err error
	if ksa3 {
		v, err = NewCipher3(key, iv)
	} else {
		v, err = NewCipher(key, iv)
	}
	if err != nil {
		t.Fatal(err)
	}
	ret := make([]byte, len(buff))
	v.XORKeyStream(ret, buff)
	return ret
}

func TestKeyLen(t *testing.T) {
	buf := get_rand(65, t)
	nul := []byte{}

	tests := []struct {
		len       int
		shouldErr bool
	}{
		{15, true},
		{16, false},
		{40, false},
		{64, false},
		{65, true},
	}

	for _, tt := range tests {
		_, err := NewCipher(buf[0:tt.len], nul)
		if !tt.shouldErr {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			if _, ok := err.(KeyIVSizeError); !ok {
				t.Fatal(err)
			}
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	cnt := 102400
	b0 := get_rand(cnt, t)
	k := get_rand(64, t)
	iv := get_rand(64, t)

	// test for KSA "0" .
	{
		b1 := cryptwith(k, iv, b0, t, false)
		b2 := cryptwith(k, iv, b1, t, false)

		// check
		if !bytes.Equal(b2, b0) {
			t.Fatalf("encrypt+decrypt got different than original\noriginal: %x\nresult:   %x\n", b0[0:50], b2[0:50])
		}
	}
	// test for KSA3
	{
		b1 := cryptwith(k, iv, b0, t, true)
		b2 := cryptwith(k, iv, b1, t, true)

		// check
		if !bytes.Equal(b2, b0) {
			t.Fatalf("encrypt+decrypt(with KSA3) got different than original\noriginal: %x\nresult:   %x\n", b0[0:50], b2[0:50])
		}
	}
}
