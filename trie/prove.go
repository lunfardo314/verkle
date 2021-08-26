package trie

import (
	"github.com/lunfardo314/verkle/kzg"
	"go.dedis.ch/kyber/v3"
	"golang.org/x/xerrors"
)

type ProofElement struct {
	C     kyber.Point // vector (node) commitment
	Index int
	Proof kyber.Point
}

type Proof struct {
	Key   []byte
	Value []byte
	Path  []*ProofElement
}

func (st *State) Prove(key []byte) (*Proof, bool) {
	value, ok := st.values.Get(key)
	if !ok {
		return nil, false
	}
	ret := &Proof{
		Key:   key,
		Value: value,
		Path:  make([]*ProofElement, 0),
	}
	rootC := st.ts.Suite.G1().Point()
	st.RootCommitment(rootC)
	st.proofPath(key, 0, rootC, ret)
	return ret, true
}

// ProveStr prove
func (st *State) ProveStr(key string) (*Proof, bool) {
	return st.Prove([]byte(key))
}

func (st *State) proofPath(path []byte, pathPosition uint16, c kyber.Point, proof *Proof) {
	assert(int(pathPosition) <= len(path), "pathPosition <=len(path)")
	node, ok := st.GetNode(path[:pathPosition])
	assert(ok, "inconsistency 1")

	pathPosition += uint16(len(node.pathFragment))
	assert(int(pathPosition) <= len(path), "int(pathPosition)<=len(path)")

	var childIdx int
	if int(pathPosition) == len(path) {
		childIdx = 256
	} else {
		childIdx = int(path[pathPosition])
	}

	pi, _ := node.proofSpot(st.ts, childIdx)
	ret := &ProofElement{
		C:     c,
		Index: childIdx,
		Proof: pi,
	}
	proof.Path = append(proof.Path, ret)
	if int(pathPosition) < len(path) {
		assert(childIdx < len(node.children), "childIdx<len(node.children)")
		st.proofPath(path, pathPosition+1, node.children[childIdx], proof)
	} else {
		assert(int(pathPosition) == len(path), "int(pathPosition) == len(path)")
	}
}

func (pr *Proof) Len() int {
	return len(pr.Path)
}

func (pr *Proof) RootCommitment(ret kyber.Point) {
	ret.Set(pr.Path[0].C)
}

func (pr *Proof) ValueCommitment(ret kyber.Scalar) {
	scalarFromBytes(ret, pr.Value)
}

func VerifyProofPath(ts *kzg.TrustedSetup, proof *Proof) error {
	v := ts.Suite.G1().Scalar()
	scalarFromBytes(v, proof.Value)
	for i := 0; i < len(proof.Path); i++ {
		if i == len(proof.Path)-1 {
			scalarFromBytes(v, proof.Value)
		} else {
			scalarFromPoint(v, proof.Path[i+1].C)
		}
		p := proof.Path[i]
		if !ts.Verify(p.C, p.Proof, v, p.Index) {
			return xerrors.Errorf("proof invalid at path position %d", i)
		}
	}
	return nil
}
