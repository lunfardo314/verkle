package trie

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lunfardo314/verkle/kzg"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"golang.org/x/crypto/blake2b"
)

// Node is a node of the 257-ary verkle trie
type Node struct {
	pathFragment  []byte
	children      [256]kyber.Point
	terminalValue kyber.Scalar
}

// NodeFromBytes
func (st *State) NodeFromBytes(data []byte) (*Node, error) {
	ret := &Node{}
	if err := ret.read(bytes.NewReader(data), st.ts.Suite); err != nil {
		return nil, err
	}
	return ret, nil
}

// Clone
func (n *Node) Clone() *Node {
	return &Node{
		pathFragment:  n.pathFragment,
		children:      n.children,
		terminalValue: n.terminalValue.Clone(),
	}
}

// Bytes
func (n *Node) Bytes() []byte {
	var buf bytes.Buffer
	if err := n.write(&buf); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// Commit calculates commitment of the node from child commitments
func (n *Node) Commit(ts *kzg.TrustedSetup) kyber.Point {
	var vect [257]kyber.Scalar
	n.Vector(ts, &vect)
	return ts.Commit(vect[:])
}

// Vector extracts vector from the node
func (n *Node) Vector(ts *kzg.TrustedSetup, ret *[257]kyber.Scalar) {
	for i, p := range n.children {
		if p == nil {
			continue
		}
		d, err := p.MarshalBinary()
		if err != nil {
			panic(err)
		}
		h := blake2b.Sum256(d)
		ret[i] = ts.Suite.G1().Scalar().SetBytes(h[:])
	}
	ret[256] = n.terminalValue
}

// proofSpot calculates proof that the vector of the node has certain value at the position i
func (n *Node) proofSpot(ts *kzg.TrustedSetup, i int) (kyber.Point, kyber.Scalar) {
	i = i % 257
	var vect [257]kyber.Scalar
	n.Vector(ts, &vect)
	return ts.Prove(vect[:], i), vect[i]
}

const (
	hasTerminalValueFlag = 0x01
	hasChildrenFlag      = 0x02
)

func (n *Node) write(w io.Writer) error {
	assert(len(n.pathFragment) < 256, "len(n.pathFragment)<256")
	if _, err := w.Write([]byte{byte(len(n.pathFragment))}); err != nil {
		return err
	}
	if _, err := w.Write(n.pathFragment); err != nil {
		return err
	}
	var smallFlags byte
	if n.terminalValue != nil {
		smallFlags = hasTerminalValueFlag
	}
	// compress children flags
	var flags [32]byte
	for i, v := range n.children {
		if v == nil {
			continue
		}
		flags[i/8] |= 0x1 << (i % 8)
		smallFlags |= hasChildrenFlag
	}

	if _, err := w.Write([]byte{smallFlags}); err != nil {
		return err
	}
	if smallFlags&hasTerminalValueFlag != 0 {
		if _, err := n.terminalValue.MarshalTo(w); err != nil {
			return err
		}
	}
	if smallFlags&hasChildrenFlag != 0 {
		if _, err := w.Write(flags[:]); err != nil {
			return err
		}
		for _, child := range n.children {
			if child == nil {
				continue
			}
			if _, err := child.MarshalTo(w); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *Node) read(r io.Reader, suite *bn256.Suite) error {
	var b1 [1]byte
	if _, err := r.Read(b1[:]); err != nil {
		return err
	}
	n.pathFragment = make([]byte, b1[0])
	if _, err := r.Read(n.pathFragment); err != nil {
		return err
	}
	var smallFlags byte
	if _, err := r.Read(b1[:]); err != nil {
		return err
	}
	smallFlags = b1[0]
	if smallFlags&hasTerminalValueFlag != 0 {
		n.terminalValue = suite.G1().Scalar()
		if _, err := n.terminalValue.UnmarshalFrom(r); err != nil {
			return err
		}
	} else {
		n.terminalValue = nil
	}
	if smallFlags&hasChildrenFlag != 0 {
		var flags [32]byte
		if _, err := r.Read(flags[:]); err != nil {
			return err
		}
		for i := range n.children {
			if flags[i/8]&(0x1<<(i%8)) != 0 {
				n.children[i] = suite.G1().Point()
				if _, err := n.children[i].UnmarshalFrom(r); err != nil {
					return err
				}
			} else {
				n.children[i] = nil
			}
		}
	}
	return nil
}

func (n *Node) String() string {
	ret := fmt.Sprintf("  pathFragment: '%s'\n", string(n.pathFragment))
	t := "none"
	if n.terminalValue != nil {
		t = n.terminalValue.String()
	}
	ret += fmt.Sprintf("  terminalValue: %s\n", t)
	ret += "children:\n"
	for i, c := range n.children {
		if c == nil {
			continue
		}
		ret += fmt.Sprintf("        %d(%c): %s\n", i, byte(i), c.String())
	}
	return ret
}
