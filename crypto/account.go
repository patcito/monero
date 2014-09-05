package crypto

// KeysFromBytes generates a public and private key from a given byte slice.
func KeysFromBytes(b []byte) (public *PublicKey, secret *SecretKey) {
	var s ECScalar
	scReduce32(s[:], b)

	point := new(geP3)

	geScalarMultBase(point, &s)
	p := geP3ToBytes(point)

	public = (*PublicKey)(p)
	secret = (*SecretKey)(&s)

	return
}
