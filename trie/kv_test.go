package trie

import (
	"testing"

	"github.com/lunfardo314/verkle/kzg"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func TestKVSBasic(t *testing.T) {
	kvs := NewSimpleKVStore()

	kvs.Set([]byte("abc"), []byte("klm"))
	require.True(t, kvs.Has([]byte("abc")))

	d, ok := kvs.Get([]byte("abc"))
	require.True(t, ok)
	require.EqualValues(t, string(d), "klm")

	kvs.Del([]byte("abc"))
	require.False(t, kvs.Has([]byte("abc")))
}

func TestPartition(t *testing.T) {
	kvs := NewSimpleKVStore()
	p1 := kvs.Partition("1")
	p2 := kvs.Partition("2")
	p3 := kvs.Partition("3")

	p1.Set([]byte("abc"), []byte("klm"))
	require.True(t, p1.Has([]byte("abc")))
	p2.Set([]byte("abc"), []byte("klm"))
	require.True(t, p1.Has([]byte("abc")))
	p3.Set([]byte("abc"), []byte("klm"))
	require.True(t, p1.Has([]byte("abc")))

	d, ok := p1.Get([]byte("abc"))
	require.True(t, ok)
	require.EqualValues(t, string(d), "klm")
	d, ok = p2.Get([]byte("abc"))
	require.True(t, ok)
	require.EqualValues(t, string(d), "klm")
	d, ok = p3.Get([]byte("abc"))
	require.True(t, ok)
	require.EqualValues(t, string(d), "klm")

	p1.Del([]byte("abc"))
	require.False(t, kvs.Has([]byte("abc")))
	d, ok = p2.Get([]byte("abc"))
	require.True(t, ok)
	require.EqualValues(t, string(d), "klm")
	d, ok = p3.Get([]byte("abc"))
	require.True(t, ok)
	require.EqualValues(t, string(d), "klm")
}

func TestNode0(t *testing.T) {
	suite := bn256.NewSuite()
	zero := suite.G1().Point().Null()
	ts, err := kzg.TrustedSetupFromSeed(suite, 257, []byte("abrakadabara"))
	require.NoError(t, err)

	t.Run("new node", func(t *testing.T) {
		n := &Node{}
		c := n.Commit(ts)
		require.True(t, c.Equal(zero))
	})
	t.Run("new node marshal", func(t *testing.T) {
		st := NewState(ts)
		n, err := st.NewNode([]byte("a"))
		require.NoError(t, err)
		data := n.Bytes()
		nBack, err := st.NodeFromBytes(data)
		require.NoError(t, err)
		require.EqualValues(t, n.Bytes(), nBack.Bytes())
	})
	t.Run("new node duplicate key", func(t *testing.T) {
		st := NewState(ts)
		_, err := st.NewNode([]byte("a"))
		require.NoError(t, err)
		_, err = st.NewNode([]byte("a"))
		require.Error(t, err)
	})
	t.Run("new node two new nodes", func(t *testing.T) {
		st := NewState(ts)
		_, err := st.NewNode([]byte("a"))
		require.NoError(t, err)
		_, err = st.NewNode([]byte("b"))
		require.NoError(t, err)
	})
}
