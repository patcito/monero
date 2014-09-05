package monero

import (
	"testing"

	"github.com/ehmry/monero/crypto"
)

const control = "42uWJwLRQRmSLm6DntgH3h2BvdLA3xqo1amRwPjQysCiii56jQE2uyG7vmQgZzCRpZarxg5LCUhPFRGE4VtHK5oqG1uvTnZ"

func TestDecodeAddress(t *testing.T) {
	_, err := DecodeAddress(control)
	if err != nil {
		t.Fatal("Error decoding address,", err)
	}
}

func BenchmarkGenerateAddress(b *testing.B) {
	h := crypto.NewHash()
	seed := h.Sum(nil)

	for i := 0; i < b.N; i++ {
		h.Write(seed)
		h.Sum(seed[:0])
		GenerateAddress(seed)
	}
}
