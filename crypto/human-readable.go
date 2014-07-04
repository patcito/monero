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

type ECScalar [32]byte

type SecretKey [32]byte

type PublicKey [32]byte

func (sec *SecretKey) Check() bool { return scCheck((*ECScalar)(sec)) }

func (sec *SecretKey) PublicKey() (*PublicKey, error) {
	if !sec.Check() {
		return nil, InvalidSecret
	}

	var point geP3
	geScalarMultBase(&point, (*ECScalar)(sec))
	s := geP3ToBytes(&point)
	return (*PublicKey)(s), nil
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

func generateKeyDerivation(pub, sec *ECScalar) (*[32]byte, error) {
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

	return geToBytes(&point2), nil
}

func hashToPoint(h []byte) *[32]byte {
	point := geFromFeFromBytesVarTime(h)
	return geToBytes(point)
}
