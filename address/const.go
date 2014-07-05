package address

import "errors"

const (
	checksumSize         = 4
	fullBlockSize        = 8
	fullEncodedBlockSize = 11

	alphabetSize = 58
)

var (
	encodedBlockSizes = [...]int{0, 2, 3, 5, 6, 7, 9, 10, 11}
	alphabet          = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	InvalidAddress    = errors.New("Invalid Address")
	CorruptAddress    = errors.New("address has invalid checksum")
)
