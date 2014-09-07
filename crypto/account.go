package crypto

/*
// KeysFromBytes generates a public and private key from a given byte slice.
func KeysFromBytes(b []byte) (public *PublicKey, secret *SecretKey) {
	var s [32]byte
	Reduce32(s, b)

	point := new(geP3)

	geScalarMultBase(point, &s)
	p := new([32]byte)
	geP3ToBytes(p, point)

	public = (*PublicKey)(p)
	secret = (*SecretKey)(&s)

	return
}
*/
