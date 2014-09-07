package crypto

import (
	"crypto/rand"
	"errors"
)

var (
	InvalidSecret    = errors.New("invalid secret key")
	InvalidPublicKey = errors.New("invalid public key")
)

type ECPoint [32]byte

type SecretKey [32]byte

type PublicKey [32]byte

// PublicFromSecret generates a public key from a secret key.
func PublicFromSecret(public, secret *[32]byte) {
	var point geP3
	geScalarMultBase(&point, secret)
	geP3ToBytes(public, &point)
}

func (sec *SecretKey) Check() bool { return scCheck((*[32]byte)(sec)) }

func (sec *SecretKey) PublicKey() (*PublicKey, error) {
	if !sec.Check() {
		return nil, InvalidSecret
	}

	var point geP3
	geScalarMultBase(&point, (*[32]byte)(sec))
	p := new([32]byte)
	geP3ToBytes(p, &point)
	return (*PublicKey)(p), nil
}

func checkKey(key []byte) bool {
	var point geP3
	return geFromBytesVarTime(&point, key)
}

// newECScalar generates a new random ECScalar
func newECScalar() *ECScalar {
	tmp := make([]byte, 64)
	rand.Read(tmp)
	s := new(ECScalar)
	scReduce(tmp, s[:])
	return s
}

func generateKeyDerivation(pub, sec *[32]byte) (*[32]byte, error) {
	var (
		point  geP3
		point2 geP2
		point3 geP1P1
	)

	if !scCheck(sec) {
		return nil, InvalidSecret
	}
	if !geFromBytesVarTime(&point, pub[:]) {
		return nil, InvalidPublicKey
	}

	geScalarMult(&point2, sec, &point)
	geMul8(&point3, &point2)
	geP1P1ToP2(&point2, &point3)

	d := new([32]byte)
	geToBytes(d, &point2)
	return d, nil
}

func hashToPoint(h []byte) *[32]byte {
	point := geFromFeFromBytesVarTime(h)
	b := new([32]byte)
	geToBytes(b, point)
	return b
}
