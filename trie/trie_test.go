package trie

import (
	"fmt"
	"golang.org/x/crypto/blake2b"
	"math/rand"
	"testing"
	"time"

	"github.com/lunfardo314/verkle/kzg"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func TestState0(t *testing.T) {
	suite := bn256.NewSuite()
	ts, err := kzg.TrustedSetupFromFile(suite, "example.setup")
	require.NoError(t, err)
	st := NewState(ts)

	require.True(t, st.Check(ts))

	proof, ok := st.Prove(nil)
	require.True(t, ok)
	rootC := ts.Suite.G1().Point()
	proof.RootCommitment(rootC)
	rootC1 := ts.Suite.G1().Point()
	st.RootCommitment(rootC1)
	require.True(t, rootC1.Equal(rootC))

	require.EqualValues(t, "", string(proof.Key))
	require.EqualValues(t, ts.Bytes(), proof.Value)
	require.EqualValues(t, 1, len(proof.Path))

	err = VerifyProofPath(st.ts, proof)
	require.NoError(t, err)
	t.Logf("\nTRIE: \n%s\n", st.StringTrie())
}

func TestString(t *testing.T) {
	suite := bn256.NewSuite()
	ts, err := kzg.TrustedSetupFromFile(suite, "example.setup")
	require.NoError(t, err)
	st := NewState(ts)
	t.Logf("\nTRIE: \n%s\n", st.StringTrie())
}

//nolint:funlen
func TestTrie1(t *testing.T) {
	suite := bn256.NewSuite()
	ts, err := kzg.TrustedSetupFromFile(suite, "example.setup")
	require.NoError(t, err)

	t.Run("1", func(t *testing.T) {
		st := NewState(ts)
		require.True(t, st.Check(ts))

		st.UpdateStr("a", "b")
		st.FlushCaches()

		proofa, ok := st.ProveStr("a")
		require.True(t, ok)
		rootC := ts.Suite.G1().Point()
		proofa.RootCommitment(rootC)
		rootC1 := ts.Suite.G1().Point()
		st.RootCommitment(rootC1)
		require.True(t, rootC1.Equal(rootC))

		require.EqualValues(t, "a", string(proofa.Key))
		require.EqualValues(t, "b", string(proofa.Value))

		err = VerifyProofPath(ts, proofa)
		require.NoError(t, err)
		t.Logf("\nTRIE: \n%s\n", st.StringTrie())
	})
	t.Run("2", func(t *testing.T) {
		st := NewState(ts)
		require.True(t, st.Check(ts))

		st.UpdateStr("a", "b")
		st.UpdateStr("ab", "bc")
		st.UpdateStr("ac", "bcd")
		st.UpdateStr("abrakadabra", "zzzz")
		st.FlushCaches()

		proofa, ok := st.ProveStr("a")
		require.True(t, ok)
		rootC := ts.Suite.G1().Point()
		proofa.RootCommitment(rootC)
		rootC1 := ts.Suite.G1().Point()
		st.RootCommitment(rootC1)
		require.True(t, rootC1.Equal(rootC))

		require.EqualValues(t, "a", string(proofa.Key))
		require.EqualValues(t, "b", string(proofa.Value))

		err = VerifyProofPath(ts, proofa)
		require.NoError(t, err)

		proofab, ok := st.ProveStr("ab")
		require.True(t, ok)
		rootC = ts.Suite.G1().Point()
		proofab.RootCommitment(rootC)
		rootC1 = ts.Suite.G1().Point()
		st.RootCommitment(rootC1)
		require.True(t, rootC1.Equal(rootC))

		require.EqualValues(t, "ab", string(proofab.Key))
		require.EqualValues(t, "bc", string(proofab.Value))

		err = VerifyProofPath(ts, proofab)
		require.NoError(t, err)

		proofzz, ok := st.ProveStr("abrakadabra")
		require.True(t, ok)
		rootC = ts.Suite.G1().Point()
		proofzz.RootCommitment(rootC)
		rootC1 = ts.Suite.G1().Point()
		st.RootCommitment(rootC1)
		require.True(t, rootC1.Equal(rootC))

		require.EqualValues(t, "abrakadabra", string(proofzz.Key))
		require.EqualValues(t, "zzzz", string(proofzz.Value))

		err = VerifyProofPath(ts, proofzz)
		require.NoError(t, err)

		t.Logf("\nTRIE: \n%s\n", st.StringTrie())
	})
	t.Run("3", func(t *testing.T) {
		st := NewState(ts)
		require.True(t, st.Check(ts))
		updateKeys(st, kvpairs1)
		t.Logf("\nTRIE: \n%s\n", st.StringTrie())
	})
	t.Run("determinism 1", func(t *testing.T) {
		st := NewState(ts)
		require.True(t, st.Check(ts))

		c1 := updateKeys(st, kvpairs1)
		t.Logf("C1 = %s", c1.String())
		c2 := updateKeys(st, kvpairs1)
		t.Logf("C1 = %s", c2.String())
		require.True(t, c1.Equal(c2))
	})
	t.Run("determinism 2", func(t *testing.T) {
		st1 := NewState(ts)
		require.True(t, st1.Check(ts))
		c1 := updateKeys(st1, kvpairs1)
		t.Logf("C1 = %s", c1.String())

		st2 := NewState(ts)
		require.True(t, st2.Check(ts))

		c2 := updateKeys(st2, kvpairs1)
		t.Logf("C1 = %s", c2.String())

		require.True(t, c1.Equal(c2))
	})
	t.Run("determinism 3", func(t *testing.T) {
		st1 := NewState(ts)
		require.True(t, st1.Check(ts))
		c1 := updateKeys(st1, kvpairs1)
		t.Logf("C1 = %s", c1.String())

		st2 := NewState(ts)
		require.True(t, st2.Check(ts))

		rpairs := randomizeKeys(kvpairs1)
		c2 := updateKeys(st2, rpairs)
		t.Logf("C1 = %s", c2.String())

		require.True(t, c1.Equal(c2))
	})
	t.Run("determinism 4", func(t *testing.T) {
		var prev kyber.Point
		for i := 0; i < 20; i++ {
			st := NewState(ts)
			require.True(t, st.Check(ts))

			rpairs := randomizeKeys(kvpairs1)
			c := updateKeys(st, rpairs)
			t.Logf("C = %s", c.String())

			if prev != nil {
				require.True(t, prev.Equal(c))
			}
			prev = c
		}
	})
}

func TestTrie2(t *testing.T) {
	suite := bn256.NewSuite()
	ts, err := kzg.TrustedSetupFromFile(suite, "example.setup")
	require.NoError(t, err)

	t.Run("1", func(t *testing.T) {
		st := NewState(ts)
		require.True(t, st.Check(ts))
		updateKeys(st, kvpairs1)
		t.Logf("\nTRIE: \n%s\n", st.StringTrie())

		for _, kv := range kvpairs1 {
			proof, ok := st.ProveStr(kv.key)
			require.True(t, ok)
			err := VerifyProofPath(st.ts, proof)
			require.NoError(t, err)
		}
	})
	t.Run("2", func(t *testing.T) {
		st := NewState(ts)
		require.True(t, st.Check(ts))

		for _, kv := range kvpairs1 {
			st.UpdateStr(kv.key, kv.value)
			st.FlushCaches()

			proof, ok := st.ProveStr(kv.key)
			require.True(t, ok)
			err := VerifyProofPath(st.ts, proof)
			require.NoError(t, err)
		}
		t.Logf("\nTRIE: \n%s\n", st.StringTrie())
	})
}

func TestTrie3(t *testing.T) {
	suite := bn256.NewSuite()
	ts, err := kzg.TrustedSetupFromFile(suite, "example.setup")
	require.NoError(t, err)

	t.Run("1", func(t *testing.T) {
		const num = 30

		st := NewState(ts)
		require.True(t, st.Check(ts))

		kpairs := genKeys(num)
		for i, kp := range kpairs {
			t.Logf("%d: %s -- %s", i, kp.key, kp.value)
		}
		updateKeys(st, kpairs)
		t.Logf("\nTRIE: \n%s\n", st.StringTrie())
	})
	t.Run("2", func(t *testing.T) {
		const num = 30

		st := NewState(ts)
		require.True(t, st.Check(ts))

		kpairs := genKeys(num)
		for i, kp := range kpairs {
			t.Logf("%d: %s -- %s", i, kp.key, kp.value)
		}
		updateKeys(st, kpairs)
		for _, kv := range kpairs {
			proof, ok := st.ProveStr(kv.key)
			t.Logf("proof len: %d, key: %s, val: %s", len(proof.Path), string(proof.Key), string(proof.Value))
			require.True(t, ok)
			err := VerifyProofPath(st.ts, proof)
			require.NoError(t, err)
		}
	})
}

func TestTrieStats(t *testing.T) {
	suite := bn256.NewSuite()
	ts, err := kzg.TrustedSetupFromFile(suite, "example.setup")
	require.NoError(t, err)
	t.Run("random", func(t *testing.T) {
		const numKeys = 10000

		st := NewState(ts)
		require.True(t, st.Check(ts))

		kpairs := genKeys(numKeys)
		t.Logf("num key/value pairs: %d", len(kpairs))
		c := updateKeys(st, kpairs)
		t.Logf("C = %s", c)

		require.True(t, hasAllKeys(st, kpairs))

		statsKVValues := GetStatsKVStore(st.values)
		t.Logf("VALUE KV:\n    value keys: %d\n    avg value key len: %f\n    avg value size: %f",
			statsKVValues.NumKeys, statsKVValues.AvgKeyLen, statsKVValues.AvgValueSize)
		//for i, n := range statsKVValues.KeyLen {
		//	t.Logf("      len %d: %d", i, n)
		//}
		statsKVTrie := GetStatsKVStore(st.trie)
		t.Logf("TRIE KV:\n    trie keys: %d\n    avg trie key len: %f\n    avg value size: %f\n",
			statsKVTrie.NumKeys, statsKVTrie.AvgKeyLen, statsKVTrie.AvgValueSize)
		for i, n := range statsKVTrie.KeyLen {
			t.Logf("      len %d: %d", i, n)
		}
		statsTrie := GetStatsTrie(st)
		t.Logf("TRIE:\n    excess factor: %d%%\n    numNodes: %d\n    avg num children: %f\n    only terminal: %d\n    number of children (incl terminal):",
			100*statsKVTrie.NumKeys/statsKVValues.NumKeys-100, statsTrie.NumNodes, statsTrie.AvgNumChildren, statsTrie.OnlyTerminal)
		for i, nch := range statsTrie.NumChildren {
			if nch != 0 {
				t.Logf("     %d: %d", i, nch)
			}
		}
		//t.Logf("\nTRIE: \n%s\n", st.StringTrie())
	})
	t.Run("random iscp style", func(t *testing.T) {
		const numKeys = 10000
		const numSC = 100

		st := NewState(ts)
		require.True(t, st.Check(ts))

		kpairs := genKeysISCP(numKeys, numSC)
		t.Logf("num key/value pairs: %d", len(kpairs))
		c := updateKeys(st, kpairs)
		t.Logf("C = %s", c)

		require.True(t, hasAllKeys(st, kpairs))

		statsKVValues := GetStatsKVStore(st.values)
		t.Logf("VALUE KV:\n    value keys: %d\n    avg value key len: %f\n    avg value size: %f",
			statsKVValues.NumKeys, statsKVValues.AvgKeyLen, statsKVValues.AvgValueSize)
		//for i, n := range statsKVValues.KeyLen {
		//	t.Logf("      len %d: %d", i, n)
		//}
		statsKVTrie := GetStatsKVStore(st.trie)
		t.Logf("TRIE KV:\n    trie keys: %d\n    avg trie key len: %f\n    avg value size: %f\n",
			statsKVTrie.NumKeys, statsKVTrie.AvgKeyLen, statsKVTrie.AvgValueSize)
		for i, n := range statsKVTrie.KeyLen {
			t.Logf("      len %d: %d", i, n)
		}
		statsTrie := GetStatsTrie(st)
		t.Logf("TRIE:\n    excess factor: %d%%\n    numNodes: %d\n    avg num children: %f\n    only terminal: %d\n    number of children (incl terminal):",
			100*statsKVTrie.NumKeys/statsKVValues.NumKeys-100, statsTrie.NumNodes, statsTrie.AvgNumChildren, statsTrie.OnlyTerminal)
		for i, nch := range statsTrie.NumChildren {
			if nch != 0 {
				t.Logf("     %d: %d", i, nch)
			}
		}
		//t.Logf("\nTRIE: \n%s\n", st.StringTrie())
	})
}

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

func updateKeys(st *State, pairs []*kvpair) kyber.Point {
	for _, kv := range pairs {
		st.UpdateStr(kv.key, kv.value)
	}
	st.FlushCaches()
	return st.RootCommitment()
}

func randomizeKeys(pairs []*kvpair) []*kvpair {
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

func genKeys(n int) []*kvpair {
	kmap := make(map[string]string)
	rand.Seed(time.Now().UnixNano())
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

func hasAllKeys(st *State, kvpairs []*kvpair) bool {
	for _, kvp := range kvpairs {
		if !st.values.Has([]byte(kvp.key)) {
			return false
		}
	}
	return true
}

func genKeysISCP(total, numSC int) []*kvpair {
	rand.Seed(time.Now().UnixNano())
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
