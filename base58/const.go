package base58

import "math/big"

const (
	fullBlockSize        = 8
	fullEncodedBlockSize = 11

	alphabetSize = 58
)

var (
	encodedBlockSizes = [...]int{0, 2, 3, 5, 6, 7, 9, 10, 11}
	alphabet          = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	radix = big.NewInt(58)
	bigZero = big.NewInt(0)
)
