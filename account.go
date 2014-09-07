package monero

import "github.com/ehmry/monero/crypto"

type Account struct {
	spendP, spendS *[32]byte
	viewP, viewS   *[32]byte
}

func (a *Account) Address() *Address {
	return &Address{spend: a.spendP, view: a.viewP}
}

func (a *Account) String() string {
	return a.Address().String()
}

func (a *Account) Mnemonic() []string {
	return BytesToWords(a.spendS[:])
}

func RecoverMnemonic(words []string) (*Account, error) {
	spendS := new([32]byte)
	if err := WordsToBytes(spendS, words); err != nil {
		return nil, err
	}

	spendP := new([32]byte)
	crypto.PublicFromSecret(spendP, spendS)

	viewS := new([32]byte)
	// the view secret key is the hash of the spend secret key
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
