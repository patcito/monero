package crypto

import "encoding/binary"

func derivationToScalar(derivation []byte, outputIndex uint64) *ECScalar {
	buf := make([]byte, 40)
	copy(buf, derivation[:])
	n := binary.PutUvarint(buf[32:], outputIndex)

	s := new(ECScalar)
	hashToScalar(s, buf[:32+n])
	return s
}

func derivePublicKey(derivation []byte, outputIndex uint64, public *ECScalar) (derivedKey *PublicKey, err error) {
	var (
		point1 geP3
		point2 geP3
		point3 geCached
		point4 geP1P1
		point5 geP2
	)
	if !geFromBytesVarTime(&point1, public[:]) {
		return nil, InvalidPublicKey
	}

	scalar := derivationToScalar(derivation, outputIndex)
	geScalarMultBase(&point2, scalar)
	geP3ToCached(&point3, &point2)
	geAdd(&point4, &point1, &point3)
	geP1P1ToP2(&point5, &point4)

	derivedKey = (*PublicKey)(geToBytes(&point5))
	return
}

func deriveSecretKey(derivation []byte, outputIndex uint64, secret *ECScalar) (derivedKey *ECScalar, err error) {
	if !scCheck(secret) {
		return nil, InvalidSecret
	}

	derivedKey = new(ECScalar)

	scalar := derivationToScalar(derivation, outputIndex)
	scAdd(derivedKey, secret, scalar)
	return derivedKey, nil
}
