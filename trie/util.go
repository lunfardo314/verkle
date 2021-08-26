package trie

import (
	"fmt"

	"go.dedis.ch/kyber/v3"
	"golang.org/x/crypto/blake2b"
)

func commonPrefix(b1, b2 []byte) []byte {
	ret := make([]byte, 0)
	for i := 0; i < len(b1) && i < len(b2); i++ {
		if b1[i] != b2[i] {
			break
		}
		ret = append(ret, b1[i])
	}
	return ret
}

func scalarFromBytes(ret kyber.Scalar, data []byte) kyber.Scalar {
	h := blake2b.Sum256(data)
	ret.SetBytes(h[:])
	return ret
}

// scalarFromPoint hashes the point and make a scalar from hash
// Note that zero point does not result in zero scalar
func scalarFromPoint(ret kyber.Scalar, point kyber.Point) kyber.Scalar {
	if point == nil {
		ret.Zero()
		return ret
	}
	pBin, err := point.MarshalBinary()
	if err != nil {
		panic(err)
	}
	scalarFromBytes(ret, pBin)
	return ret
}

func assert(cond bool, msg interface{}) {
	if !cond {
		panic(fmt.Sprintf("failed assertion: '%v'", msg))
	}
}
