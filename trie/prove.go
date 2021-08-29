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

// Prove return a valid proof.
// If the key is present in the state, it contains the proof of presence of it in the key
// If the key is absent, the field Value == nil and the proof is a prove of commitment to 0 value
// in the last element of the path
func (st *State) Prove(key []byte) (*Proof, bool) {
	value, ok := st.values.Get(key)
	if !ok {
		// value does not exists in the state
		// will prove its absence
		value = nil
	}
	ret := &Proof{
		Key:   key,
		Value: value,
		Path:  make([]*ProofElement, 0),
	}
	rootC := st.ts.Suite.G1().Point()
	st.RootCommitment(rootC)
	st.mustProofPath(key, 0, rootC, ret)
	return ret, !ret.IsProofOfAbsence()
}

// ProveStr prove
func (st *State) ProveStr(key string) (*Proof, bool) {
	return st.Prove([]byte(key))
}

// always succeeds if the key is present in the state
func (st *State) mustProofPath(path []byte, pathPosition uint16, c kyber.Point, proof *Proof) {
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
	var absence bool
	if childIdx < 256 {
		// the path does not exist. The proof is about absence of the key in the state
		absence = node.children[childIdx] == nil
	} else {
		// the path does not exist. The proof is about absence of the key in the state
		absence = node.terminalValue == nil
	}
	if absence {
		return
	}
	if int(pathPosition) < len(path) {
		assert(childIdx < len(node.children), "childIdx<len(node.children)")
		st.mustProofPath(path, pathPosition+1, node.children[childIdx], proof)
	} else {
		assert(int(pathPosition) == len(path), "int(pathPosition) == len(path)")
	}
}

func (pr *Proof) IsProofOfAbsence() bool {
	return pr.Value == nil
}

func (pr *Proof) Len() int {
	return len(pr.Path)
}

func (pr *Proof) RootCommitment(ret kyber.Point) {
	ret.Set(pr.Path[0].C)
}

func VerifyProof(ts *kzg.TrustedSetup, proof *Proof) error {
	v := ts.Suite.G1().Scalar()
	for i := 0; i < len(proof.Path); i++ {
		if i == len(proof.Path)-1 {
			if proof.Value != nil {
				scalarFromBytes(v, proof.Value)
			} else {
				// proving absence
				v = ts.ZeroG1
			}
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
