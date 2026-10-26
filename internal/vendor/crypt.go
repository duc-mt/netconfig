// ==============================================================================
// File name:     crypt.go
// Description:   SHA-512 crypt(3) ("$6$") using only the standard library.
// License:       MIT
// ==============================================================================
package vendor

import (
	"crypto/rand"
	"crypto/sha512"
	"io"
)

// Junos takes a pre-hashed password on the command line. Its alternative,
// "plain-text-password", prompts interactively for the secret, which a
// line-oriented session cannot answer, so the hash is computed here and the
// plaintext never leaves the host.

const (
	cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	cryptRounds   = 5000 // the crypt(3) default; no "rounds=" prefix is emitted
	cryptSaltLen  = 16
)

// saltSource supplies random bytes for salts; tests replace it.
var saltSource io.Reader = rand.Reader

// newSalt returns 16 random characters from the crypt alphabet.
func newSalt() (string, error) {
	raw := make([]byte, cryptSaltLen)
	if _, err := io.ReadFull(saltSource, raw); err != nil {
		return "", err
	}
	out := make([]byte, cryptSaltLen)
	for i, b := range raw {
		out[i] = cryptAlphabet[int(b)&0x3f]
	}
	return string(out), nil
}

// sha512Crypt implements Ulrich Drepper's SHA-crypt for "$6$" with the default
// round count. salt must already be at most 16 characters.
func sha512Crypt(password, salt string) string {
	pw, sl := []byte(password), []byte(salt)

	b := sha512.New()
	b.Write(pw)
	b.Write(sl)
	b.Write(pw)
	sumB := b.Sum(nil)

	a := sha512.New()
	a.Write(pw)
	a.Write(sl)
	for n := len(pw); n > 0; n -= sha512.Size {
		if n > sha512.Size {
			a.Write(sumB)
		} else {
			a.Write(sumB[:n])
		}
	}
	for n := len(pw); n > 0; n >>= 1 {
		if n&1 != 0 {
			a.Write(sumB)
		} else {
			a.Write(pw)
		}
	}
	sumA := a.Sum(nil)

	dp := sha512.New()
	for range pw {
		dp.Write(pw)
	}
	sumDP := dp.Sum(nil)
	p := repeatTo(sumDP, len(pw))

	ds := sha512.New()
	for i := 0; i < 16+int(sumA[0]); i++ {
		ds.Write(sl)
	}
	sumDS := ds.Sum(nil)
	s := repeatTo(sumDS, len(sl))

	c := sumA
	for i := 0; i < cryptRounds; i++ {
		h := sha512.New()
		if i&1 != 0 {
			h.Write(p)
		} else {
			h.Write(c)
		}
		if i%3 != 0 {
			h.Write(s)
		}
		if i%7 != 0 {
			h.Write(p)
		}
		if i&1 != 0 {
			h.Write(c)
		} else {
			h.Write(p)
		}
		c = h.Sum(nil)
	}

	var out []byte
	put := func(b2, b1, b0 byte, n int) {
		w := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
		for i := 0; i < n; i++ {
			out = append(out, cryptAlphabet[w&0x3f])
			w >>= 6
		}
	}
	order := [][3]int{
		{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26},
		{6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32},
		{12, 33, 54}, {34, 55, 13}, {56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38},
		{18, 39, 60}, {40, 61, 19}, {62, 20, 41},
	}
	for _, o := range order {
		put(c[o[0]], c[o[1]], c[o[2]], 4)
	}
	put(0, 0, c[63], 2)
	return "$6$" + salt + "$" + string(out)
}

// repeatTo returns the first n bytes of src repeated as often as needed.
func repeatTo(src []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		take := n - len(out)
		if take > len(src) {
			take = len(src)
		}
		out = append(out, src[:take]...)
	}
	return out
}

// HashPassword returns a "$6$" SHA-512 crypt hash with a fresh random salt.
func HashPassword(password string) (string, error) {
	salt, err := newSalt()
	if err != nil {
		return "", err
	}
	return sha512Crypt(password, salt), nil
}
