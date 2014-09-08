package monero

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	//"github.com/ehmry/monero/crypto"
)

func TestWordToBytes(t *testing.T) {
	rand.Seed(time.Now().Unix())

	words := make([]string, 24)

	for i := 0; i < 24; i++ {
		words[i] = wordsArray[rand.Intn(numwords)]
	}

	var b [32]byte
	WordsToBytes(&b, words)
	result, err := BytesToWords(b[:])
	if err != nil {
		t.Fatalf("error recovering word list, %s", err)
	}
	if len(result) != 24 {
		t.Fatalf("recovered word list was %d, not 24 long", len(result))
	}

	for i := 0; i < 24; i++ {
		if words[i] != result[i] {
			t.Errorf("Word mismatch: %02d - %q != %q", i, words[i], result[i])
		}
	}
}

type test struct {
	addr  string
	words []string
}

var tests = []*test{
	{
		"43GVEVSitCqRxtuRXWbpsu6trCmHXhqNM4myNZka86JMMtw75eWVduKRJ2rz3yjTUoCPf9mkJHjfC9JRZUM7f3fSM52vYej",
		strings.Fields("happen former recall kill tonight magic mercy threw somehow arrive meant sheet charm victim once indeed hug bubble wash storm hill bid respect excuse"),
	},
	{
		"4A4ZprYVAdC8iKm1bVwPmQi2Q7KtEZL94d7tCHEaQV9FBa4UgeUCDaRAeqvSRgwbeQ67xrSmABVQyMZX2KuuNAV3Bk8cLW1",
		strings.Fields("empty favorite good iron spend memory grand dark direction brain out pleasure climb hardly out claim neither lick hidden button aim shiver gently treat"),
	},
	{
		"468vZRyTA7F5mjPFXTFcwp3bsTBHbMLztKD9B3FbHZewiyHXBWKmAgFcQChApA5gM34eAyX6siSpy2vwifZ8Cd6nSuq5Dau",
		strings.Fields("handle brother whistle realize money upon leg level doubt shove count memory wonderful pop clear huge tap less age circle slowly weather gasp grief"),
	},
	{
		"455MJ7FvGZL8rmxHSjE4z7AFsCJTmF9L2U3nLw4fD7zDRT1K5xjYUadVEcuekSbDereYgAQcWrJGyd42K4L9bTgb7WKJiFV",
		strings.Fields("claim pride forward strain piece group torture stream balance unknown lick common useless empty prayer good sunlight trouble return snap gone focus measure scale"),
	},
}

func TestRecovery(t *testing.T) {
	for _, test := range tests {
		account, err := RecoverAccountWithMnemonic(test.words)
		if err != nil {
			t.Fatal("mnemonic recovery failed,", err)
		}
		if test.addr != account.String() {
			t.Errorf("mnemonic recovery failed,\nwanted %s\ngot    %s", test.addr, account)
		}
		words := account.Mnemonic()
		for i := 0; i < len(words); i++ {
			if test.words[i] != words[i] {
				t.Errorf("Mnemonic() failed %d,\nwanted %s\ngot    %s", i, test.addr, account)
			}
		}
	}
}
