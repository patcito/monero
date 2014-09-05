package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"regexp"

	"github.com/ehmry/monero"
	"github.com/ehmry/monero/crypto"
)

func main() {
	var err error

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Atleast one regular expression must be specified")
		os.Exit(1)
	}

	res := make([]*regexp.Regexp, len(os.Args)-1)
	for i, arg := range os.Args[1:] {
		res[i], err = regexp.Compile(arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid regexp %q, %s", arg, err)
			os.Exit(1)
		}
	}

	seed := make([]byte, 32)
	h := crypto.NewHash()
	rand.Read(seed)

	for {
		addr := monero.GenerateAddress(seed)
		for _, re := range res {
			text, _ := addr.MarshalText()
			if re.Match(text) {
				fmt.Fprintf(os.Stdout, "%s - %x", addr, seed)
				os.Exit(0)
			}
		}
		h.Sum(seed[:0])
	}
}
