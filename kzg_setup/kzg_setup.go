// the program kzg_setup generates new trusted setup for the KZG calculations from the
// secret entered from the keyboard and saves generated setup into the file
// Usage: kzg_setup <file name>
package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"syscall"

	"github.com/lunfardo314/verkle/kzg"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/term"
)

const (
	minSeed     = 20
	defaultFile = "example.setup"
	D           = 257
)

func main() {
	if len(os.Args) > 2 {
		fmt.Printf("Usage: kzg_setup <file name>\n")
		return
	}
	fname := defaultFile
	if len(os.Args) == 2 {
		fname = os.Args[1]
	}
	fmt.Printf("generating new trusted KXG setup to file '%s'... \n", fname)
	var seed []byte
	var err error
	for {
		fmt.Printf("please enter seed > %d symbols and press ENTER (CTRL-C to exit) > ", minSeed)
		seed, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Printf("\nerror: %v\n", err)
			continue
		}
		if len(seed) < minSeed {
			fmt.Printf("\nerror: seed too short\n")
			continue
		}
		fmt.Println()
		break
	}
	h := blake2b.Sum256(seed)
	// destroy seed
	for i := range seed {
		seed[i] = 0
	}
	// hash seed random number of times
	for i := 0; i < 10+rand.Intn(90); i++ {
		h = blake2b.Sum256(h[:])
	}
	suite := bn256.NewSuite()
	s := suite.G1().Scalar()
	s.SetBytes(h[:])
	h = [32]byte{} // destroy secret
	omega, _ := kzg.GenRootOfUnityQuasiPrimitive(suite, D)
	tr, err := kzg.TrustedSetupFromSecretPowers(suite, D, omega, s)
	s.Zero() // // destroy secret
	if err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(fname, tr.Bytes(), 0600); err != nil {
		panic(err)
	}
	fmt.Printf("success. The trusted setup has been generated and saved into the file '%s'\n", fname)
	if _, err = kzg.TrustedSetupFromFile(suite, fname); err != nil {
		fmt.Printf("reading trusted setup back from file '%s': %v\nFAIL\n", fname, err)
	} else {
		fmt.Printf("reading trusted setup back from file '%s': OK\nSUCCESS\n", fname)
	}
}
