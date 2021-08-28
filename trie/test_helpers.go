package trie

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"golang.org/x/crypto/blake2b"
	"math/rand"
	"testing"
)

type kvpair struct {
	key   string
	value string
}

var kvpairs1 = []*kvpair{
	{"a", "1"},
	{"ab", "2"},
	{"ac", "3"},
	{"abrakadabra", "4"},
	{"abrak2adab", "5"},
	{"abrak1adabra", "6"},
	{"abrak3adabra", "7"},
	{"abrak2", "8"},
	{"abrak3", "9"},
	{"abrak3a", "10"},
	{"abrak3ab", "11"},
	{"abrak3abc", "12"},
	{"abrak3a", "10"},
	{"abrak3ab", "11"},
	{"abrak3abc", "12"},
}

func UpdateKeys(st *State, pairs []*kvpair) kyber.Point {
	for _, kv := range pairs {
		st.UpdateStr(kv.key, kv.value)
	}
	st.FlushCaches()
	return st.RootCommitment()
}

func RandomizeKeys(pairs []*kvpair) []*kvpair {
	ret := make([]*kvpair, len(pairs))
	for i := range pairs {
		r := rand.Intn(len(ret))
		for j := r; ; j = (j + 1) % len(pairs) {
			if ret[j] == nil {
				ret[j] = pairs[i]
				break
			}
		}
	}
	return ret
}

func GenKeys(n int) []*kvpair {
	kmap := make(map[string]string)
	for i := 0; len(kmap) != n; i++ {
		r := rand.Intn(70)
		buf := make([]byte, r+1)
		rand.Read(buf)
		kmap[string(buf)] = fmt.Sprintf("%d", i)
		i++
	}
	ret := make([]*kvpair, n)
	i := 0
	for k, v := range kmap {
		ret[i] = &kvpair{
			key:   k,
			value: v,
		}
		i++
	}
	return ret
}

func HasAllKeys(st *State, kvpairs []*kvpair) bool {
	for _, kvp := range kvpairs {
		if !st.values.Has([]byte(kvp.key)) {
			return false
		}
	}
	return true
}

func GenKeysISCP(total, numSC int) []*kvpair {
	scs := make([][4]byte, numSC)
	for i := range scs {
		r := fmt.Sprintf("%d", rand.Intn(10000)%5843)
		scKey := blake2b.Sum256([]byte(r))
		copy(scs[i][:], scKey[0:4])
	}
	kmap := make(map[string]string)
	for i := 0; len(kmap) != total; i++ {
		r := rand.Intn(60)
		buf := make([]byte, r+5)
		rand.Read(buf)
		copy(buf[0:4], scs[rand.Intn(numSC)][:]) // emulate SC prefix
		buf[4] = byte(rand.Intn(256) % 10)       // emulate limited number of state variables
		kmap[string(buf)] = fmt.Sprintf("%d", i)
	}
	ret := make([]*kvpair, total)
	i := 0
	for k, v := range kmap {
		ret[i] = &kvpair{
			key:   k,
			value: v,
		}
		i++
	}
	return ret
}

func PrintSizeDistrib(t *testing.T, distrib map[int]int) {
	maxIdx := 1
	for i := range distrib {
		if i < 0 {
			panic("i < 1")
		}
		if i > maxIdx {
			maxIdx = i
		}
	}
	arr := make([]int, maxIdx+1)
	for i, v := range distrib {
		arr[i] = v
	}
	for i, v := range arr {
		t.Logf(" size %d: %d", i, v)
	}
}
