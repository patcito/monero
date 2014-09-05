package crypto

import (
	"hash"

	"code.google.com/p/go.crypto/sha3"
)

// NewHash returns a standard hash.Hash for use with Monero.
// The current algorithm is Keccak256 (sha3).
func NewHash() hash.Hash { return sha3.NewKeccak256() }

func hashToScalar(s *ECScalar, b []byte) {
	h := sha3.NewKeccak256()
	h.Write(b)
	digest := make([]byte, 64)
	h.Sum(digest[:0])

	scReduce(s[:], digest)
}

func hashToEC(key *ECScalar) *geP3 {
	var (
		point2 geP1P1
	)
	r := new(geP3)
	h := sha3.NewKeccak256()
	h.Write(key[:])
	digest := h.Sum(nil)
	point := geFromFeFromBytesVarTime(digest)

	geMul8(&point2, point)
	geP1P1ToP3(r, &point2)
	return r
}
