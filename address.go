package monero

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/ehmry/monero/base58"
	"github.com/ehmry/monero/crypto"
)

const (
	checksumSize = 4

	// tacotime> '2' is bytecoin, '4' is monero
	tag = 0x12
)

var (
	InvalidAddressLength = errors.New("invalid address length")
	CorruptAddress       = errors.New("address has invalid checksum")
	InvalidAddressTag    = errors.New("address has invalid prefix")
	InvalidAddress       = errors.New("address contains invalid keys")
)

func DecodeAddress(s string) (*PublicAddress, error) {
	pa := new(PublicAddress)
	err := pa.UnmarshalText([]byte(s))
	if err != nil {
		return nil, err
	}
	return pa, nil
}

type PublicAddress struct {
	spend, view *crypto.PublicKey
}

func (a *PublicAddress) MarshalBinary() (data []byte, err error) {
	// make this long enough to hold a full hash on the end
	data = make([]byte, 104)
	// copy tag
	n := binary.PutUvarint(data, tag)

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

func (a *PublicAddress) UnmarshalBinary(data []byte) error {
	if len(data) < checksumSize {
		return InvalidAddressLength
	}

	// Verify checksum
	checksum := data[len(data)-checksumSize:]
	data = data[:len(data)-checksumSize]
	hash := crypto.NewHash()
	hash.Write(data)
	digest := hash.Sum(nil)
	if !bytes.Equal(checksum, digest[:checksumSize]) {
		return CorruptAddress
	}

	// check address prefix
	t, n := binary.Uvarint(data)
	data = data[n:]

	if t != tag {
		return InvalidAddressTag
	}

	if len(data) != 64 {
		return InvalidAddressLength
	}

	if a.spend == nil {
		a.spend = new(crypto.PublicKey)
	}
	if a.view == nil {
		a.view = new(crypto.PublicKey)
	}

	copy(a.spend[:], data[:32])
	copy(a.view[:], data[32:])
	// don't check the keys yet
	return nil
}

func (a *PublicAddress) String() string {
	text, _ := a.MarshalText()
	return string(text)
}

func (a *PublicAddress) MarshalText() (text []byte, err error) {
	data, _ := a.MarshalBinary()
	text = make([]byte, base58.EncodedLen(len(data)))
	base58.Encode(text, data)
	return text, nil
}

func (a *PublicAddress) UnmarshalText(text []byte) error {

	// Decode from base58
	b := make([]byte, base58.DecodedLen(len(text)))
	_, err := base58.Decode(b, text)
	if err != nil {
		return err
	}
	return a.UnmarshalBinary(b)
}

func GenerateAddress(seed []byte) *PublicAddress {
	spend, _ := crypto.KeysFromBytes(seed)

	h := crypto.NewHash()
	h.Write(seed)
	seed = h.Sum(nil)

	view, _ := crypto.KeysFromBytes(seed)

	return &PublicAddress{spend, view}
}
