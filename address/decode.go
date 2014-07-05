package address

import (
	"encoding/binary"
	"bytes"
	"io"
	"io/ioutil"
	"math/big"
	"strings"

	"github.com/ehmry/monero/crypto"
	//"github.com/ehmry/encoding/basex"
)

func decodeAddr(s string) (tag uint64, data []byte, err error) {
	b, err := DecodeString(s)
	if err != nil {
		return
	}

	if len(b) < checksumSize {
		err = InvalidAddress
		return
	}

	checksum := b[len(b)-checksumSize:]
	b = b[:len(b)-checksumSize]
	hash := crypto.NewHash()
	hash.Write(b)
	digest := hash.Sum(nil)
	if !bytes.Equal(checksum, digest[:checksumSize]) {
		err = CorruptAddress
		return
	}

	var n int
	tag, n = binary.Uvarint(b)
	data = b[n:]

	return
}

type decoder struct {
	err  error
	r    io.Reader
	buf  [fullEncodedBlockSize]byte
	nbuf int
	out  []byte //leftover decoded output
}

func NewDecoder(r io.Reader) io.Reader {
	return &decoder{r: r, out: make([]byte, 0, fullBlockSize)}
}

func (d *decoder) Read(p []byte) (n int, err error) {
	if d.err != nil {
		return 0, d.err
	}

	// Use leftover decode ouput from last read.
	if len(d.out) > 0 {
		n = copy(p, d.out)
		d.out = d.out[n:]
		return n, nil
	}

	var nn int
	// Read a block
	for len(p) > fullBlockSize {
		nn, d.err = d.r.Read(d.buf[d.nbuf:fullEncodedBlockSize])
		if d.nbuf+nn != fullEncodedBlockSize {
			d.nbuf += nn
			break
		}
		decodeBlock(p, d.buf[:fullEncodedBlockSize])
		d.nbuf = 0
		p = p[fullBlockSize:]
		n += fullBlockSize
	}
	if d.err == io.EOF {
		if d.nbuf != 0 {
			if len(p) >= d.nbuf {
				n += decodeBlock(p, d.buf[:d.nbuf])
			} else {
				decodeBlock(d.out, d.buf[:d.nbuf])
			}
		}
	}
	return n, d.err
}

func DecodeString(s string) ([]byte, error) {
	return ioutil.ReadAll(NewDecoder(strings.NewReader(s)))
}

func decodeBlock(dst, src []byte) int {
	answer := big.NewInt(0)
	j := big.NewInt(1)

	for i := len(src) - 1; i >= 0; i-- {
		tmp := bytes.IndexByte(alphabet, src[i])
		if tmp == -1 {
			if src[i] == 0x00 {
				continue
			}
			return 0
		}
		idx := big.NewInt(int64(tmp))
		tmp1 := big.NewInt(0)
		tmp1.Mul(j, idx)

		answer.Add(answer, tmp1)
		j.Mul(j, big.NewInt(alphabetSize))
	}

	l := encodedLengths[len(src)]
	tmp := answer.Bytes()
	copy(dst[l-len(tmp):], tmp)
	return l
}

var encodedLengths = [...]int{0, 0, 1, 2, 2, 3, 4, 5, 6, 6, 7, 8}

func uint64To8be(x uint64) []byte {
	var l int
	switch {
	case x < 0xFF:
		l = 1
	case x < 0xFFFF:
		l = 2
	case x < 0xFFFFFF:
		l = 3
	case x < 0xFFFFFFFF:
		l = 4
	case x < 0xFFFFFFFFFF:
		l = 5
	case x < 0xFFFFFFFFFFFF:
		l = 6
	case x < 0xFFFFFFFFFFFFFF:
		l = 7
	default:
		l = 8
	}
	b := make([]byte, l)
	for i := l - 1; i > -1; i-- {
		b[i] = byte(x)
		x >>= 8
	}
	return b
}

func mul128(multiplier, multiplicand uint64) (n, productHi uint64) {
	// multiplier   = ab = a * 2^32 + b
	// multiplicand = cd = c * 2^32 + d
	// ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
	a := multiplier >> 32
	b := multiplier & 0xFFFFFFFF
	c := multiplicand >> 32
	d := multiplicand & 0xFFFFFFFF

	ac := a * c
	ad := a * d
	bc := b * c
	bd := b * d

	adbc := ad + bc
	var adbcCarry uint64
	if adbc < ad {
		adbcCarry = 1
	}

	// multiplier * multiplicand = product_hi * 2^64 + product_lo
	productLo := bd + (adbc << 32)
	var productLoCarry uint64
	if productLo < bd {
		productLoCarry = 1
	}
	productHi = ac + (adbc >> 32) + (adbcCarry << 32) + productLoCarry
	return productLo, productHi
}
