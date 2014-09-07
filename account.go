package monero

import (
	"errors"

	"github.com/ehmry/monero/crypto"
)

// Account contains public and private keys for the spend and view
// aspects of a Monero account.
type Account struct {
	spendP, spendS *[32]byte
	viewP, viewS   *[32]byte
}

// Address returns the address of a given account.
func (a *Account) Address() *Address {
	return &Address{spend: a.spendP, view: a.viewP}
}

func (a *Account) String() string {
	return a.Address().String()
}

// Mnemonic returns an Electrum style mnemonic representation 
// of the account secret key.
func (a *Account) Mnemonic() []string {
	return BytesToWords(a.spendS[:])
}

// Recover recovers an account using a secret key.
func RecoverAccount(secret []byte) (*Account, error) {
	if len(secret) != 32 {
		return nil, errors.New("cannot recover, key has invalid length")
	}

	spendS := new([32]byte)
	copy(spendS[:], secret)

	spendP := new([32]byte)
	crypto.PublicFromSecret(spendP, spendS)

	// the view secret key is the hash of the spend secret key
	viewS := new([32]byte)
	h := crypto.NewHash()
	h.Write(spendS[:])
	h.Sum(viewS[:0])
	crypto.Reduce32(viewS, viewS)

	viewP := new([32]byte)
	crypto.PublicFromSecret(viewP, viewS)

	return &Account{
		spendP: spendP,
		spendS: spendS,
		viewP:  viewP,
		viewS:  viewS,
	}, nil
}

// RecoverAccountWithMnemonic recovers an account 
// with an Electrum style word list.
func RecoverAccountWithMnemonic(words []string) (*Account, error) {
	buf := new([32]byte)
	if err := WordsToBytes(buf, words); err != nil {
		return nil, err
	}
	return RecoverAccount(buf[:])
}
