package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
)

func SafePrime(bits uint) *big.Int {
	var p *big.Int
	checks := int(math.Max(float64(bits)/16, 20))
	for {
		p, _ = rand.Prime(rand.Reader, int(bits)-1)
		p.Add(p.Lsh(p, 1), big.NewInt(1))

		if p.ProbablyPrime(checks) {
			return p
		}
	}
}

func PrimRoot(max *big.Int) *big.Int {
	subMax := new(big.Int).Sub(max, big.NewInt(1))
	for {
		res, _ := rand.Int(rand.Reader, max)

		cmpVal := new(big.Int).Exp(res, subMax, max)

		if cmpVal.Cmp(big.NewInt(1)) == 0 {
			return res
		}
	}
}

func main() {
	const numOfBits uint = 64

	privateAlice, _ := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	privateBob, _ := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))

	p := SafePrime(numOfBits)
	g := PrimRoot(p)

	printArray := make([]byte, int(math.Ceil(float64(numOfBits)/8.0)))

	privateAlice.FillBytes(printArray)
	fmt.Println("Alice Private: ", hex.EncodeToString(printArray))

	privateBob.FillBytes(printArray)
	fmt.Println("Bob Private: ", hex.EncodeToString(printArray))

	g.FillBytes(printArray)
	fmt.Println("g: ", hex.EncodeToString(printArray))

	p.FillBytes(printArray)
	fmt.Println("p: ", hex.EncodeToString(printArray))

	ag := new(big.Int).Exp(g, privateAlice, p)

	ag.FillBytes(printArray)
	fmt.Println("a^g mod p: ", hex.EncodeToString(printArray))

	bg := new(big.Int).Exp(g, privateBob, p)

	bg.FillBytes(printArray)
	fmt.Println("b^g mod p: ", hex.EncodeToString(printArray))

	key := new(big.Int).Exp(bg, privateAlice, p)

	key.FillBytes(printArray)
	fmt.Println("Alice's key: ", hex.EncodeToString(printArray))

	key = new(big.Int).Exp(ag, privateBob, p)

	key.FillBytes(printArray)
	fmt.Println("Bob's key: ", hex.EncodeToString(printArray))
}
