package base58

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
	"math/big"
	"strings"

	"github.com/ehmry/monero/crypto"
)

const checksumSize = 4

func decodeAddr(s string) (tag uint64, data []byte) {
	b, err := DecodeString(s)
	if err != nil {
		return
	}

	if len(b) < checksumSize {
		return
	}

	checksum := b[len(b)-checksumSize:]
	b = b[:len(b)-checksumSize]
	hash := crypto.NewHash()
	hash.Write(b)
	digest := hash.Sum(nil)
	if !bytes.Equal(checksum, digest[:checksumSize]) {
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
	// Use leftover decode ouput from last read.
	if len(d.out) != 0 {
		n = copy(p, d.out)
		d.out = d.out[n:]
		return n, nil
	}
	if d.err != nil {
		return 0, d.err
	}

	var nn int
	// Read a block
	for len(p) >= fullBlockSize {
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
			if len(p) >= fullEncodedBlockSize-d.nbuf {
				n += decodeBlock(p, d.buf[:d.nbuf])
			} else {
				n += decodeBlock(d.out, d.buf[:d.nbuf])
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
