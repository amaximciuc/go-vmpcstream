// Package VMPC implements the VMPC cipher, as described in
// http://www.vmpcfunction.com/cipher.htm
package vmpc

import "strconv"

// A Cipher is an instance of VMPC using a particular key.
type Cipher struct {
	p    [256]byte
	n, s byte
}

type KeyIVSizeError int

func (k KeyIVSizeError) Error() string {
	return "VMPC: invalid key/iv size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new Cipher.  The key argument should be the
// key, at least 16 bytes and at most 64 bytes.
// iv is the initialization vector. if it's a zero-legth byte-slice - it's ignored;
// otherwise should be at least 16 bytes and at most 64 bytes
func NewCipher(key, iv []byte) (*Cipher, error) {
	c := &Cipher{}
	for i := uint32(0); i < 256; i++ {
		c.p[i] = byte(i) // permutarea initiala
	}
	if err := c._KSARound(key); err != nil {
		return nil, err
	}
	if 0 == len(iv) {
		return c, nil
	}
	// aplic iv..
	if err := c._KSARound(iv); err != nil {
		return nil, err
	}
	return c, nil
}

// NewCipher3 creates and returns a new Cipher(just as NewCipher) _but_ with KSA3
// key scheduling algorithm
func NewCipher3(key, iv []byte) (*Cipher, error) {
	c, err := NewCipher(key, iv)
	if err != nil {
		return nil, err
	}
	if err := c._KSARound(key); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cipher) _KSARound(key_or_iv []byte) error {
	buflen := len(key_or_iv)
	if buflen < 16 || buflen > 64 {
		return KeyIVSizeError(buflen)
	}
	s := c.s
	for m := 0; m < 768; m++ {
		n := byte(m)
		s = c.p[byte(s+c.p[n]+key_or_iv[m%buflen])]
		c.p[n], c.p[s] = c.p[s], c.p[n]
	}
	c.s = s
	return nil
}

// Reset zeros the key data so that it will no longer appear in the
// process's memory.
func (c *Cipher) Reset() {
	for i := range c.p {
		c.p[i] = 0
	}
	c.n, c.s = 0, 0
}

// XORKeyStream sets dst to the result of XORing src with the key stream.
// Dst and src may be the same slice but otherwise should not overlap.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	for k, v := range src {
		n := byte(k)
		c.s = c.p[byte(c.s+c.p[byte(k)])]
		dst[k] = v ^ c.p[byte(c.p[c.p[c.s]]+1)]
		c.p[n], c.p[c.s] = c.p[c.s], c.p[n]
	}
}
