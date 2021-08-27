package trie

import (
	"math/rand"
	"testing"
	"time"

	"github.com/lunfardo314/verkle/kzg"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func BenchmarkBuildTrie(b *testing.B) {
	suite := bn256.NewSuite()
	ts, _ := kzg.TrustedSetupFromFile(suite, "example.setup")
	rand.Seed(time.Now().UnixNano())

	st := NewState(ts)

	kpairs := GenKeys(b.N)
	b.Logf("num key/value pairs: %d", len(kpairs))

	b.ResetTimer()
	c := UpdateKeys(st, kpairs)
	b.Logf("C = %s", c)
}

func BenchmarkProveVerify(b *testing.B) {
	suite := bn256.NewSuite()
	ts, _ := kzg.TrustedSetupFromFile(suite, "example.setup")
	rand.Seed(time.Now().UnixNano())
	const numKeys = 10000

	st := NewState(ts)

	kpairs := GenKeys(numKeys)
	b.Logf("num key/value pairs: %d", len(kpairs))
	c := UpdateKeys(st, kpairs)
	b.Logf("C = %s", c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := rand.Intn(len(kpairs))
		proof, _ := st.ProveStr(kpairs[idx].key)
		//b.Logf("proof len: %d, key len: %d", len(proof.Path), len(proof.Key))
		err := VerifyProofPath(st.ts, proof)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkProof(b *testing.B) {
	suite := bn256.NewSuite()
	ts, _ := kzg.TrustedSetupFromFile(suite, "example.setup")
	rand.Seed(time.Now().UnixNano())
	const numKeys = 1000

	st := NewState(ts)

	kpairs := GenKeys(numKeys)
	b.Logf("num key/value pairs: %d", len(kpairs))
	c := UpdateKeys(st, kpairs)
	b.Logf("C = %s", c)
	b.Logf("b.N = %d", b.N)

	b.ResetTimer()
	proofs := make([]*Proof, b.N)
	for i := 0; i < b.N; i++ {
		idx := rand.Intn(len(kpairs))
		proofs[i], _ = st.ProveStr(kpairs[idx].key)
	}
}

func BenchmarkVerify(b *testing.B) {
	suite := bn256.NewSuite()
	ts, _ := kzg.TrustedSetupFromFile(suite, "example.setup")
	rand.Seed(time.Now().UnixNano())
	const numKeys = 1000

	st := NewState(ts)

	kpairs := GenKeys(numKeys)
	b.Logf("num key/value pairs: %d", len(kpairs))
	c := UpdateKeys(st, kpairs)
	b.Logf("C = %s", c)
	b.Logf("b.N = %d", b.N)

	proofs := make([]*Proof, b.N)
	for i := 0; i < b.N; i++ {
		idx := rand.Intn(len(kpairs))
		proofs[i], _ = st.ProveStr(kpairs[idx].key)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := VerifyProofPath(st.ts, proofs[i])
		if err != nil {
			panic(err)
		}
	}
}
