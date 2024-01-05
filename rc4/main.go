package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func GenerateNumbers(key []byte) []byte {
	s := make([]byte, 256)

	for i := 0; i < 256; i += 1 {
		s[i] = byte(i)
	}

	j := byte(0)
	for i := 0; i < 256; i += 1 {
		j = j + s[i] + key[i%len(key)]

		s[i], s[j] = s[j], s[i]
	}

	return s
}

func CreateGeneratorK(s []byte) func() byte {
	i := byte(0)
	j := byte(0)
	return func() byte {
		i += 1
		j += s[i]
		s[i], s[j] = s[j], s[i]
		t := s[i] + s[j]

		return s[t]
	}
}

func main() {
	inputFile := flag.String("in", "", "file(with path) wich will be encrypted")
	outputFile := flag.String("out", "", "file(with path) wich will be encrypted")
	key := flag.String("key", "", "hex key with which will be used.")

	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Error: input file required")
		return
	}

	if *outputFile == "" {
		fmt.Println("Error: output file required")
		return
	}

	if len([]byte(*key)) < 5 || len([]byte(*key)) > 256 {
		fmt.Println("Error: key should be between 5 and 256 symbols")
		return
	}

	r, err := os.OpenFile(*inputFile, os.O_RDONLY, 0777)
	if err != nil {
		fmt.Println("Error on opening input file")
		return
	}
	defer r.Close()

	w, err := os.OpenFile(*outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		fmt.Println("Error on opening output file")
		return
	}

	defer w.Close()

	s := GenerateNumbers([]byte(*key))
	generator := CreateGeneratorK(s)

	buffer := make([]byte, 256)

	for {
		n, err := r.Read(buffer)

		if err == io.EOF {
			break
		}

		if n < 256 {
			buffer = buffer[:256-n]
		}

		for i, _ := range buffer {
			buffer[i] ^= generator()
		}

		w.Write(buffer)

		if len(buffer) < 256 {
			break
		}
	}
}
