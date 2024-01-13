package main

import (
	"crypto/rand"
	"elGamal/constants"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
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
	inputFile := flag.String("in", "", "file(with path) wich will be encrypted")
	outputFile := flag.String("out", "", "file(with path) wich will be encrypted")
	mode := flag.String("mode", "", "mode which will be used. Available are: genKey, encode, decode")
	keyFile := flag.String("keyFile", "", "base filename wich will be used to store keys. Files will be <name>.pub and <name>.pvt")
	numOfBits := flag.Uint("keyLength", 512, "Len of key in bits")

	flag.Parse()

	switch *mode {
	case "genKey":
		if *keyFile == "" {
			fmt.Println("Error: key filename should be defined for key generation")
			return
		}

		if *numOfBits < 64 {
			fmt.Println("Error: key should be at least 64 bits long")
			return
		}

		p := SafePrime(*numOfBits)
		g := PrimRoot(p)

		x, _ := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))

		y := new(big.Int).Exp(g, x, p)

		openKeyFile, err := os.OpenFile(*keyFile+".pub", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0777)

		if err != nil {
			fmt.Println("Error: opening public key file")
			return
		}
		defer openKeyFile.Close()

		privateKeyFile, err := os.OpenFile(*keyFile+".pvt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0777)

		if err != nil {
			fmt.Println("Error: opening private key file")
			return
		}
		defer privateKeyFile.Close()

		openKeyFile.Write([]byte(constants.OPEN_KEY_MSG))
		privateKeyFile.Write([]byte(constants.PRIVATE_KEY_MSG))

		printArray := make([]byte, uint64(math.Ceil(float64(*numOfBits)/8.0)))

		y.FillBytes(printArray)
		openKeyFile.Write(printArray)
		fmt.Println("y: ", y)

		g.FillBytes(printArray)
		openKeyFile.Write(printArray)
		fmt.Println("g: ", g)

		p.FillBytes(printArray)
		privateKeyFile.Write(printArray)
		openKeyFile.Write(printArray)
		fmt.Println("p: ", p)

		printArray = make([]byte, 8)
		x.FillBytes(printArray)
		privateKeyFile.Write(printArray)
		fmt.Println("x: ", x)

	case "encode":
		if *inputFile == "" {
			fmt.Println("Error: input file required")
			return
		}

		if *outputFile == "" {
			fmt.Println("Error: output file required")
			return
		}

		if *keyFile == "" {
			fmt.Println("Error: keyfile required")
			return
		}

		keyF, err := os.OpenFile(*keyFile, os.O_RDONLY, 0777)

		if err != nil {
			fmt.Println("Error: opening key file")
			return
		}
		defer keyF.Close()

		sizeBytes := make([]byte, len(constants.OPEN_KEY_MSG))

		n, err := keyF.Read(sizeBytes)

		if err != nil {
			fmt.Println("Error: reading key file")
			return
		}

		if n < len(constants.OPEN_KEY_MSG) || string(sizeBytes) != constants.OPEN_KEY_MSG {
			fmt.Println("Error: key file may be corrupted")
			return
		}

		stats, _ := os.Stat(*keyFile)

		keySize := uint64(stats.Size()) - uint64(len(constants.OPEN_KEY_MSG))

		sizeBytes = make([]byte, keySize)

		n, err = keyF.Read(sizeBytes)

		if err != nil {
			fmt.Println("Error: reading key file")
			return
		}

		if uint64(n) < keySize {
			fmt.Println("Error: key file may be corrupted")
			return
		}

		y := new(big.Int).SetBytes(sizeBytes[0 : len(sizeBytes)/3])
		g := new(big.Int).SetBytes(sizeBytes[len(sizeBytes)/3 : 2*len(sizeBytes)/3])
		p := new(big.Int).SetBytes(sizeBytes[2*len(sizeBytes)/3:])

		k, _ := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))

		k = k.Add(k, big.NewInt(1))

		input, err := os.OpenFile(*inputFile, os.O_RDONLY, 0777)

		if err != nil {
			fmt.Println("Error: opening input file")
			return
		}
		defer input.Close()

		output, err := os.OpenFile(*outputFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0777)

		if err != nil {
			fmt.Println("Error: opening output file")
			return
		}
		defer output.Close()

		inputStats, _ := os.Stat(*inputFile)
		size := new(big.Int).SetInt64(inputStats.Size())

		a := new(big.Int).Exp(g, k, p)
		b := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(y, k, p), new(big.Int).Mod(size, p)), p)

		keySize /= 3
		printArr := make([]byte, keySize)

		a.FillBytes(printArr)
		output.Write(printArr)

		b.FillBytes(printArr)
		output.Write(printArr)

		buffer := make([]byte, keySize-1)
		outBuffer := make([]byte, keySize)
		partMsg := new(big.Int)

		for {
			n, err = input.Read(buffer)

			if err == io.EOF {
				break
			}

			if err != nil {
				fmt.Println("Error: reding from input file")
			}

			k, _ := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))

			k = k.Add(k, big.NewInt(1))

			partMsg.SetBytes(buffer)

			a := new(big.Int).Exp(g, k, p)
			b := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(y, k, p), new(big.Int).Mod(partMsg, p)), p)

			a.FillBytes(outBuffer)
			output.Write(outBuffer)

			b.FillBytes(outBuffer)
			output.Write(outBuffer)
		}
	case "decode":
		if *inputFile == "" {
			fmt.Println("Error: input file required")
			return
		}

		if *outputFile == "" {
			fmt.Println("Error: output file required")
			return
		}

		if *keyFile == "" {
			fmt.Println("Error: keyfile required")
			return
		}

		keyF, err := os.OpenFile(*keyFile, os.O_RDONLY, 0777)

		if err != nil {
			fmt.Println("Error: opening key file")
			return
		}
		defer keyF.Close()

		sizeBytes := make([]byte, len(constants.PRIVATE_KEY_MSG))

		n, err := keyF.Read(sizeBytes)

		if err != nil {
			fmt.Println("Error: reading key file")
			return
		}

		if n < len(constants.PRIVATE_KEY_MSG) || string(sizeBytes) != constants.PRIVATE_KEY_MSG {
			fmt.Println("Error: key file may be corrupted")
			return
		}

		stat, _ := os.Stat(*keyFile)

		keySize := uint64(stat.Size()) - uint64(len(constants.PRIVATE_KEY_MSG))

		sizeBytes = make([]byte, keySize)

		n, err = keyF.Read(sizeBytes)

		if err != nil {
			fmt.Println("Error: reading key file")
			return
		}

		if uint64(n) != keySize {
			fmt.Println("Error: key file may be corrupted")
			return
		}

		keySize -= 8
		p := new(big.Int).SetBytes(sizeBytes[:keySize])
		x := new(big.Int).SetBytes(sizeBytes[keySize:])

		input, err := os.OpenFile(*inputFile, os.O_RDONLY, 0777)

		if err != nil {
			fmt.Println("Error: opening input file")
			return
		}
		defer input.Close()

		sizeBytes = make([]byte, keySize*2)
		n, err = input.Read(sizeBytes)

		if err != nil {
			fmt.Println("Error: reading input file")
			return
		}

		if uint64(n) != keySize*2 {
			fmt.Println("Error: wrong key or file is corrupted")
			return
		}

		sizeEncA := new(big.Int).SetBytes(sizeBytes[:keySize])
		sizeEncB := new(big.Int).SetBytes(sizeBytes[keySize:])

		sizeDec := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(sizeEncA, new(big.Int).Sub(new(big.Int).Sub(p, big.NewInt(1)), x), p), new(big.Int).Mod(sizeEncB, p)), p).Int64()

		output, err := os.OpenFile(*outputFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0777)

		if err != nil {
			fmt.Println("Error: opening output file")
			return
		}
		defer output.Close()

		buffer := make([]byte, keySize*2)
		outBuffer := make([]byte, keySize)
		totalRead := uint64(0)

		for {
			n, err = input.Read(buffer)

			if err == io.EOF {
				break
			}

			if err != nil {
				fmt.Println("Error: reding from input file")
				return
			}

			if uint64(n) != keySize*2 {
				fmt.Println("Error: wrong key or file is corrupted")
				return
			}

			totalRead += uint64(n/2) - 1

			a := new(big.Int).SetBytes(buffer[:keySize])
			b := new(big.Int).SetBytes(buffer[keySize:])

			msgDecoded := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(a, new(big.Int).Sub(new(big.Int).Sub(p, big.NewInt(1)), x), p), new(big.Int).Mod(b, p)), p)

			msgDecoded.FillBytes(outBuffer)

			if totalRead > uint64(sizeDec) {
				outBuffer = outBuffer[:keySize-(totalRead-uint64(sizeDec))]
			}

			output.Write(outBuffer[1:])
		}
	default:
		fmt.Println("Error: Invalid mode")
	}
}
