package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	//"testing"

	"github.com/ehmry/monero"
	"github.com/ehmry/monero/base58"
	"github.com/ehmry/monero/crypto"
)

var (
	bench, convert bool
	skip           int

	res []*regexp.Regexp
)

func init() {
	//flag.BoolVar(&bench, "bench", false, "run a benchmark")
	flag.BoolVar(&convert, "convert", false, "convert a hex seed to a mnemonic seed")
	flag.IntVar(&skip, "skip", 2, "skip the first N characters when matching regexps")
}

func die(msg ...interface{}) {
	fmt.Fprintln(os.Stderr, msg...)
	os.Exit(1)
}

func main() {
	var err error

	flag.Parse()
	args := flag.Args()

	if convert {
		if len(args) < 1 {
			die("Error: no hex seed specified")
		}
		b, err := hex.DecodeString(args[0])
		if err != nil {
			die(err)
		}
		words := strings.Join(monero.BytesToWords(b), " ")
		fmt.Fprintln(os.Stdout, words)
		os.Exit(0)
	}

	if len(args) < 1 {
		die("Error: atleast one regular expression must be specified")
	}

	res = make([]*regexp.Regexp, len(args))
	for i, arg := range args {
		res[i], err = regexp.Compile(arg)
		if err != nil {
			die("invalid regexp %q, %s", arg, err)

		}
	}

	//if bench {
	//	r := testing.Benchmark(benchmark)
	//	fmt.Println(r)
	//} else {
	find()
	//}
}

func find() {
	c := make(chan *[32]byte)
	for i := 0; i < runtime.NumCPU(); i++ {
		go findWorker(c)
	}

	result := <-c

	addr := monero.GenerateAddress(result)
	fmt.Fprintf(os.Stdout, "%s - %x\n", addr, result[:])
	os.Exit(0)
}

func findWorker(c chan *[32]byte) {
	var public, secret [32]byte

	slice := secret[:]
	rand.Read(slice)

	enc := make([]byte, 11)
	raw := make([]byte, 8)
	raw[0] = 0x12 // the network tag

	h := crypto.NewHash()

	for {
		// need to encode multiples of 8 bytes
		crypto.PublicFromSecret(&public, &secret)
		copy(raw[1:], public[:7])
		base58.Encode(enc, raw)

		for _, re := range res {
			if re.Match(enc[skip:]) {
				c <- &secret
				return
			}
		}

		h.Write(slice)
		h.Sum(secret[:0])
	}
}

/*
func benchmark(b *testing.B) {
	for i := 0; i < b.N; i++ {
		crypto.Reduce32(&secret, &secret)

		// need to encode multiples of 8 bytes
		crypto.PublicFromSecret(&public, &secret)
		copy(raw[1:], public[:7])
		base58.Encode(enc, raw)

		for _, re := range res {
			re.Match(enc)
		}

		h.Write(slice)
		h.Sum(slice[:0])
	}
}
*/
