package monero

import (
	"bytes"
	"errors"

	"github.com/ehmry/monero/base58"
	"github.com/ehmry/monero/crypto"
)

const ChecksumSize = 4

// tacotime> '2' is bytecoin, '4' is monero
var Tag = byte(0x12)

var (
	InvalidAddressLength = errors.New("invalid address length")
	CorruptAddress       = errors.New("address has invalid checksum")
	InvalidAddressTag    = errors.New("address has invalid prefix")
	InvalidAddress       = errors.New("address contains invalid keys")
)

func DecodeAddress(s string) (*Address, error) {
	pa := new(Address)
	err := pa.UnmarshalText([]byte(s))
	if err != nil {
		return nil, err
	}
	return pa, nil
}

type Address struct {
	spend, view *[32]byte
}

func (a *Address) MarshalBinary() (data []byte, err error) {
	// make this long enough to hold a full hash on the end
	data = make([]byte, 104)
	// copy tag
	n := 1
	data[0] = Tag

	//copy keys
	copy(data[n:], a.spend[:])
	copy(data[n+32:], a.view[:])

	// checksum
	hash := crypto.NewHash()
	hash.Write(data[:n+64])
	// hash straight to the slice
	hash.Sum(data[:n+64])
	return data[:n+68], nil
}

func (a *Address) UnmarshalBinary(data []byte) error {
	if len(data) < ChecksumSize {
		return InvalidAddressLength
	}

	// Verify checksum
	checksum := data[len(data)-ChecksumSize:]
	data = data[:len(data)-ChecksumSize]
	hash := crypto.NewHash()
	hash.Write(data)
	digest := hash.Sum(nil)
	if !bytes.Equal(checksum, digest[:ChecksumSize]) {
		return CorruptAddress
	}

	// check address prefix
	if data[0] != Tag {
		return InvalidAddressTag
	}

	data = data[1:]

	if len(data) != 64 {
		return InvalidAddressLength
	}

	if a.spend == nil {
		a.spend = new([32]byte)
	}
	if a.view == nil {
		a.view = new([32]byte)
	}

	copy(a.spend[:], data[:32])
	copy(a.view[:], data[32:])
	// don't check the keys yet
	return nil
}

func (a *Address) String() string {
	text, _ := a.MarshalText()
	return string(text)
}

func (a *Address) MarshalText() (text []byte, err error) {
	data, _ := a.MarshalBinary()
	text = make([]byte, base58.EncodedLen(len(data)))
	base58.Encode(text, data)
	return text, nil
}

func (a *Address) UnmarshalText(text []byte) error {

	// Decode from base58
	b := make([]byte, base58.DecodedLen(len(text)))
	_, err := base58.Decode(b, text)
	if err != nil {
		return err
	}
	return a.UnmarshalBinary(b)
}

// GenerateAddress generates an address from a secret key.
func GenerateAddress(seed *[32]byte) *Address {
	var secret [32]byte
	copy(secret[:], seed[:])
	spend := new([32]byte)
	crypto.PublicFromSecret(spend, &secret)

	// the view secret key is the hash of the spend secret key
	h := crypto.NewHash()
	h.Write(secret[:])
	h.Sum(secret[:0])

	view := new([32]byte)
	crypto.PublicFromSecret(view, &secret)

	return &Address{spend: spend, view: view}
}
