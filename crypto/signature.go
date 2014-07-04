package crypto

//import "crypto/rand"

type Signature struct {
	c, r ECScalar
}

/*
func generateSignature(prefixHash []byte, public *PublicKey, secret *SecretKey) *Signature {
	var (
		tmp3 geP3
		k    ECScalar
	)
	l := len(prefixHash)
	buf := make([]byte, l+64)

	copy(buf, prefixHash)
	copy(buf[l:], public[:])

	rand.Read(k[:])

	geScalarMultBase(&tmp3, &k)
	copy(buf[l+32:], geP3ToBytes(&tmp3)[:])

	sig := new(Signature)
	hashToScalar(&sig.c, buf)
	scMulSub(&sig.r, &sig.c, secret[:], k[:])
	return sig
}
*/

func checkSignature(prefixHash []byte, pub *PublicKey, sig []byte) bool {
	var (
		tmp2 geP2
		tmp3 geP3
		c    ECScalar
	)

	buf := make([]byte, 96)
	copy(buf[:32], prefixHash)
	copy(buf[32:64], pub[:])

	if !geFromBytesVarTime(&tmp3, pub[:]) {
		return false
	}

	// still need a consistant way to pass arrays around
	var sigC, sigR ECScalar
	copy(sigC[:], sig[:32])
	copy(sigR[:], sig[32:])

	if !scCheck(&sigC) || !scCheck(&sigR) {
		return false
	}
	geDoubleScalarMultBaseVarTime(&tmp2, &sigC, &tmp3, &sigR)
	copy(buf[64:], geToBytes(&tmp2)[:])
	hashToScalar(&c, buf)
	scSub(&c, &c, &sigC)
	return !scIsNonZero(&c)
}

func generateKeyImage(public, secret *ECScalar) *[32]byte {
	var point2 geP2

	point := hashToEC(public)
	geScalarMult(&point2, secret, point)
	return geToBytes(&point2)

}

type ringSignature struct {
	hash [32]byte
	a    []ECPoint
	b    []ECPoint
}

func checkRingSignature(prefixHash, image []byte, pubs []*ECScalar, sig []byte) bool {
	var (
		imageUnp geP3
		imagePre geDsmp
		sum, h   ECScalar
	)

	if !geFromBytesVarTime(&imageUnp, image) {
		return false
	}

	geDsmPrecomp(&imagePre, &imageUnp)

	//if (len(sig) % 64) != 0 {
	//	return true
	//}
	sigs := make([]*Signature, len(sig)/64)
	j := 0
	k := 32
	for i := 0; i < len(sigs); i++ {
		s := new(Signature)
		copy(s.c[:], sig[j:k])
		j += 32
		k += 32
		copy(s.r[:], sig[j:k])
		sigs[i] = s
		j += 32
		k += 32
	}

	buf := make([]byte, 32+len(sig))
	copy(buf, prefixHash)
	j = 32
	k = 64

	for i := 0; i < len(pubs); i++ {
		var (
			tmp2 geP2
			tmp3 geP3
		)
		if !scCheck(&sigs[i].c) || !scCheck(&sigs[i].r) {
			return false
		}

		if !geFromBytesVarTime(&tmp3, pubs[i][:]) {
			panic("abort()")
		}

		geDoubleScalarMultBaseVarTime(&tmp2, &sigs[i].c, &tmp3, &sigs[i].r)
		copy(buf[j:k], geToBytes(&tmp2)[:])
		j += 32
		k += 32
		tmp3 = *hashToEC(pubs[i])

		geDoubleScalarMultPrecompVarTime(&tmp2, &sigs[i].r, &tmp3, &sigs[i].c, &imagePre)
		copy(buf[j:k], geToBytes(&tmp2)[:])
		j += 32
		k += 32
		scAdd(&sum, &sum, &sigs[i].c)
	}

	hashToScalar(&h, buf)
	scSub(&h, &h, &sum)
	return !scIsNonZero(&h)
}
