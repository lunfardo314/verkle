package trie

import (
	"bytes"
	"fmt"

	"github.com/lunfardo314/verkle/kzg"
	"go.dedis.ch/kyber/v3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/xerrors"
)

// State represents kv store plus trie
type State struct {
	ts                  *kzg.TrustedSetup
	store               KVStore
	values              KVStore
	trie                KVStore
	root                KVStore
	rootCommitmentCache kyber.Point
	valueCache          map[string][]byte
	nodeCache           map[string]*Node
}

const (
	prefixValues         = "v"
	prefixTrie           = "t"
	prefixRootCommitment = "r"
)

func NewState(ts *kzg.TrustedSetup) *State {
	store := NewSimpleKVStore()
	ret := &State{
		ts:                  ts,
		store:               store,
		values:              store.Partition(prefixValues),
		trie:                store.Partition(prefixTrie),
		root:                store.Partition(prefixRootCommitment),
		rootCommitmentCache: ts.Suite.G1().Point().Null(),
		nodeCache:           make(map[string]*Node),
		valueCache:          make(map[string][]byte),
	}
	// initially trie has null commitments at nil key
	ret.trie.Set(nil, (&Node{}).Bytes())

	data := ts.Bytes()
	ret.StoreValue(nil, data)
	hts := blake2b.Sum256(data)
	commitTrustedSetup := ts.Suite.G1().Scalar().SetBytes(hts[:])
	ret.updateKey(nil, 0, &ret.rootCommitmentCache, commitTrustedSetup)

	ret.FlushCaches()
	assert(ret.Check(ts), "consistency check failed")
	return ret
}

func (st *State) NewNode(key []byte) (*Node, error) {
	_, ok := st.GetNode(key)
	if ok {
		return nil, xerrors.Errorf("node with the key '%s' already exists", string(key))
	}
	st.nodeCache[string(key)] = &Node{}
	return st.nodeCache[string(key)], nil
}

func (st *State) GetValue(key []byte) ([]byte, bool) {
	ret, ok := st.valueCache[string(key)]
	if ok {
		return ret, true
	}
	ret, ok = st.values.Get(key)
	if !ok {
		return nil, false
	}
	return ret, true
}

func (st *State) mustGetNode(key []byte) *Node {
	nodeBin, ok := st.trie.Get(key)
	assert(ok, fmt.Sprintf("can't get node for key '%s'", string(key)))
	node, err := st.NodeFromBytes(nodeBin)
	assert(err == nil, err)
	return node
}

func (st *State) GetNode(key []byte) (*Node, bool) {
	node, ok := st.nodeCache[string(key)]
	if ok {
		return node, true
	}
	nodeBin, ok := st.trie.Get(key)
	if !ok {
		return nil, false
	}
	node, err := st.NodeFromBytes(nodeBin)
	assert(err == nil, err)

	st.nodeCache[string(key)] = node
	return node, true
}

func (st *State) StoreValue(key, value []byte) {
	st.valueCache[string(key)] = value
}

func (st *State) StoreNode(key []byte, node *Node) {
	st.nodeCache[string(key)] = node
}

func (st *State) FlushCaches() {
	for k, v := range st.valueCache {
		st.values.Set([]byte(k), v)
	}
	for k, v := range st.nodeCache {
		st.trie.Set([]byte(k), v.Bytes())
	}
	rootBin, err := st.rootCommitmentCache.MarshalBinary()
	assert(err == nil, err)

	st.root.Set(nil, rootBin)
	st.valueCache = make(map[string][]byte)
	st.nodeCache = make(map[string]*Node)
}

func (st *State) RootCommitment(ret ...kyber.Point) kyber.Point {
	var ret1 kyber.Point
	if len(ret) == 0 {
		ret1 = st.ts.Suite.G1().Point()
	} else {
		ret1 = ret[0]
	}
	rootBin, ok := st.root.Get(nil)
	assert(ok, "inconsistency")
	err := ret1.UnmarshalBinary(rootBin)
	assert(err == nil, err)
	return ret1
}

// UpdateStr for testing
func (st *State) UpdateStr(key, value string) {
	st.Update([]byte(key), []byte(value))
}

func (st *State) Update(key, value []byte) {
	st.StoreValue(key, value)
	vCommit := st.ts.Suite.G1().Scalar()
	scalarFromBytes(vCommit, value)
	st.updateKey(key, 0, &st.rootCommitmentCache, vCommit)
}

func (st *State) updateKey(path []byte, pathPosition int, updateCommitment *kyber.Point, valueCommitment kyber.Scalar) {
	assert(pathPosition <= len(path), "pathPosition <= len(path)")
	if len(path) == 0 {
		path = []byte{}
	}
	key := path[:pathPosition]
	node, ok := st.GetNode(key)
	if !ok {
		// node for the path[:pathPosition] does not exist
		// create a new one, put rest of the path into the fragment
		// Commit to terminal value
		var err error
		node, err = st.NewNode(key)
		assert(err == nil, err)

		node.pathFragment = path[pathPosition:]
		st.updateTerminalValue(node, updateCommitment, valueCommitment)
		return
	}
	// node for the path[:pathPosition] exists
	prefix := commonPrefix(node.pathFragment, path[pathPosition:])
	assert(len(prefix) <= len(node.pathFragment), "len(prefix)<= len(node.pathFragment)")
	// the following parameters define how it goes:
	// - len(path)
	// - pathPosition
	// - len(node.pathFragment)
	// - len(prefix)
	nextPathPosition := pathPosition + len(prefix)
	assert(nextPathPosition <= len(path), "nextPathPosition <= len(path)")

	if len(prefix) == len(node.pathFragment) {
		// pathFragment is part of the path. No need for a fork, continue the path
		if nextPathPosition == len(path) {
			// reached the terminal value on this node
			st.updateTerminalValue(node, updateCommitment, valueCommitment)
		} else {
			assert(nextPathPosition < len(path), "nextPathPosition < len(path)")
			// didn't reach the end of the path
			// choose direction and continue down the path of the child
			childIndex := path[nextPathPosition]

			var oldCommitment kyber.Point
			if node.children[childIndex] != nil {
				oldCommitment = st.ts.Suite.G1().Point()
				oldCommitment.Set(node.children[childIndex])
			}
			// recursively update the rest of the path
			st.updateKey(path, nextPathPosition+1, &node.children[childIndex], valueCommitment)
			st.updateCommitment(updateCommitment, childIndex, oldCommitment, node.children[childIndex])
		}
		return
	}
	assert(len(prefix) < len(node.pathFragment), "len(prefix) < len(node.pathFragment)")

	// need for the fork of the pathFragment
	// continued branch is part of the fragment
	keyContinue := make([]byte, pathPosition+len(prefix)+1)
	copy(keyContinue, path)
	keyContinue[len(keyContinue)-1] = node.pathFragment[len(prefix)]

	// nodeContinue continues old path
	nodeContinue, err := st.NewNode(keyContinue)
	assert(err == nil, err)
	nodeContinue.pathFragment = node.pathFragment[len(prefix)+1:]
	nodeContinue.children = node.children
	nodeContinue.terminalValue = node.terminalValue

	// adjust the old node. It will hold 2 commitments to the forked nodes
	childIndexContinue := keyContinue[len(keyContinue)-1]
	node.pathFragment = prefix
	node.children = [256]kyber.Point{}
	node.terminalValue = nil

	// previous commitment must exist
	assert(*updateCommitment != nil, "*updateCommitment != nil")
	node.children[childIndexContinue] = (*updateCommitment).Clone()

	if pathPosition+len(prefix) == len(path) {
		// no need for the new node
		node.terminalValue = valueCommitment
	} else {
		// create the new node
		keyFork := path[:pathPosition+len(prefix)+1]
		assert(len(keyContinue) == len(keyFork), "len(keyContinue)==len(keyFork)")
		nodeFork, err := st.NewNode(keyFork)
		assert(err == nil, err)
		nodeFork.pathFragment = path[len(keyFork):]
		nodeFork.terminalValue = valueCommitment
		childForkIndex := keyFork[len(keyFork)-1]
		node.children[childForkIndex] = nodeFork.Commit(st.ts)
	}
	*updateCommitment = node.Commit(st.ts)
}

// updateTerminalValue updates terminal value of the node
// Returns delta for the upstream commitments
func (st *State) updateTerminalValue(n *Node, updateCommitment *kyber.Point, valueCommitment kyber.Scalar) {
	delta := st.ts.Suite.G1().Scalar()
	if n.terminalValue != nil {
		// already has terminal value
		if valueCommitment == nil {
			delta.Neg(n.terminalValue)
		} else {
			delta.Sub(valueCommitment, n.terminalValue)
		}
	} else {
		if valueCommitment == nil {
			delta.Zero()
		} else {
			delta.Set(valueCommitment)
		}
	}
	n.terminalValue = valueCommitment
	deltaP := st.ts.Suite.G1().Point().Mul(delta, st.ts.LagrangeBasis[256])
	if *updateCommitment == nil {
		*updateCommitment = deltaP
	} else {
		(*updateCommitment).Add(*updateCommitment, deltaP)
	}
}

func (st *State) updateCommitment(updateCommitment *kyber.Point, childIndex byte, oldC, newC kyber.Point) {
	deltaScalar := scalarFromPoint(st.ts.Suite.G1().Scalar(), oldC)
	newScalar := scalarFromPoint(st.ts.Suite.G1().Scalar(), newC)
	deltaScalar.Sub(newScalar, deltaScalar)
	deltaP := st.ts.Suite.G1().Point()
	deltaP.Mul(deltaScalar, st.ts.LagrangeBasis[childIndex])
	if *updateCommitment == nil {
		*updateCommitment = deltaP
	} else {
		(*updateCommitment).Add(*updateCommitment, deltaP)
	}
}

// Check checks consistency with the provided trusted setup
// The trie always has to contain proof of binary data of the trusted setup present at nil key
func (st *State) Check(ts *kzg.TrustedSetup) bool {
	v, ok := st.GetValue(nil)
	if !ok {
		return false
	}
	if !bytes.Equal(ts.Bytes(), v) {
		return false
	}
	if !bytes.Equal(st.ts.Bytes(), v) {
		return false
	}
	rootProof, ok := st.Prove(nil)
	if !ok {
		return false
	}
	return VerifyProof(ts, rootProof) == nil
}

func (st *State) StringTrie() string {
	ret := fmt.Sprintf("root commitment: %s\n", st.RootCommitment())
	for _, k := range st.trie.Keys() {
		ret += fmt.Sprintf("'%s':\n%s\n", k, st.mustGetNode([]byte(k)).String())
	}
	return ret
}

type StatsKVStore struct {
	NumKeys      int
	AvgKeyLen    float64
	KeyLen       []int
	AvgValueSize float64
}

func GetStatsKVStore(kvs KVStore) *StatsKVStore {
	ret := &StatsKVStore{}
	kl := make(map[int]int)
	maxLen := 0
	sumKeyLen := 0
	sumValueLen := 0
	for _, k := range kvs.Keys() {
		ret.NumKeys++
		sumKeyLen += len(k)
		n := kl[len(k)]
		kl[len(k)] = n + 1
		if len(k) > maxLen {
			maxLen = len(k)
		}
		value, ok := kvs.Get([]byte(k))
		if !ok {
			panic("key not found")
		}
		sumValueLen += len(value)
	}
	ret.KeyLen = make([]int, maxLen+1)
	for l, n := range kl {
		ret.KeyLen[l] = n
	}
	ret.AvgKeyLen = float64(sumKeyLen) / float64(ret.NumKeys)
	ret.AvgValueSize = float64(sumValueLen) / float64(ret.NumKeys)
	return ret
}

type StatsTrie struct {
	NumNodes       int
	AvgNumChildren float64
	NumChildren    [258]int
	OnlyTerminal   int
}

func GetStatsTrie(st *State) *StatsTrie {
	ret := &StatsTrie{}
	sumChildren := 0

	for _, k := range st.trie.Keys() {
		ret.NumNodes++
		node, ok := st.GetNode([]byte(k))
		if !ok {
			panic("can't get node")
		}
		numCh := 0
		for _, ch := range node.children {
			if ch != nil {
				numCh++
			}
		}
		if node.terminalValue != nil {
			if numCh == 0 {
				ret.OnlyTerminal++
			}
			numCh++
		}
		ret.NumChildren[numCh]++
		sumChildren += numCh
	}
	ret.AvgNumChildren = float64(sumChildren) / float64(ret.NumNodes)
	return ret
}
