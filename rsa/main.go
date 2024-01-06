package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"rsa/constants"
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

func generateKeys(numOfBytes uint) (n *big.Int, d *big.Int) {
	halfNumOfBits := numOfBytes / 2
	p := SafePrime(halfNumOfBits)
	q := SafePrime(halfNumOfBits)

	n = new(big.Int).Mul(p, q)

	pEuler := new(big.Int).Sub(p, big.NewInt(1))
	qEuler := new(big.Int).Sub(q, big.NewInt(1))

	euler := new(big.Int).Mul(pEuler, qEuler)

	d = new(big.Int).ModInverse(constants.E, euler)

	return
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

		numOfBytes := uint64(math.Ceil(float64(*numOfBits) / 8.0))

		n, d := generateKeys(*numOfBits)

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

		openKeyFile.Write([]byte("RSA OPEN KEY"))
		privateKeyFile.Write([]byte("RSA PRIVATE KEY"))

		openKeyLenBytes := make([]byte, numOfBytes)

		n.FillBytes(openKeyLenBytes)

		openKeyFile.Write(openKeyLenBytes)
		privateKeyFile.Write(openKeyLenBytes)

		d.FillBytes(openKeyLenBytes)

		privateKeyFile.Write(openKeyLenBytes)
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

		key := new(big.Int).SetBytes(sizeBytes)

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
		sizeEncoded := new(big.Int).Exp(new(big.Int).SetInt64(inputStats.Size()), constants.E, key)
		sizeBytes = make([]byte, keySize)

		sizeEncoded.FillBytes(sizeBytes)

		output.Write(sizeBytes)

		buffer := make([]byte, keySize)
		partMsg := new(big.Int)

		for {
			n, err = input.Read(buffer)

			if err == io.EOF {
				break
			}

			if err != nil {
				fmt.Println("Error: reding from input file")
			}

			partMsg.SetBytes(buffer)

			partMsg = partMsg.Exp(partMsg, constants.E, key)

			partMsg.FillBytes(buffer)

			output.Write(buffer)
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

		if keySize < 128 {
			fmt.Println("Error: too short key. File may be corrupted")
			return
		}

		n, err = keyF.Read(sizeBytes)

		if err != nil {
			fmt.Println("Error: reading key file")
			return
		}

		if uint64(n) != keySize {
			fmt.Println("Error: key file may be corrupted")
			return
		}

		keySize /= 2
		N := new(big.Int).SetBytes(sizeBytes[:keySize])
		d := new(big.Int).SetBytes(sizeBytes[keySize:])

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

		sizeBytes = make([]byte, keySize)
		n, err = input.Read(sizeBytes)

		if err != nil {
			fmt.Println("Error: reading input file")
			return
		}

		if uint64(n) != keySize {
			fmt.Println("Error: wrong key or file is corrupted")
			return
		}

		sizeEnc := new(big.Int).SetBytes(sizeBytes)
		sizeDec := uint64(new(big.Int).Exp(sizeEnc, d, N).Int64())

		buffer := make([]byte, keySize)
		totalRead := uint64(0)
		partMsg := new(big.Int)

		for {
			n, err = input.Read(buffer)

			if err == io.EOF {
				break
			}

			if err != nil {
				fmt.Println("Error: reding from input file")
				return
			}

			if uint64(n) < keySize {
				fmt.Println("Error: wrong key or file is corrupted")
				return
			}

			totalRead += uint64(n)

			partMsg.SetBytes(buffer)

			partMsg.Exp(partMsg, d, N)

			partMsg.FillBytes(buffer)

			if totalRead > sizeDec {
				buffer = buffer[:keySize-(totalRead-sizeDec)]
			}

			output.Write(buffer)
		}
	default:
		fmt.Println("Error: Invalid mode")
	}
}
