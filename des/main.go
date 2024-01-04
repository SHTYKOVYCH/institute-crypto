package main

import (
	"des/des"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

func main() {
	decrypt := flag.Bool("d", false, "whether to decrypt or not")
	inputFile := flag.String("in", "", "file(with path) wich will be encrypted")
	outputFile := flag.String("out", "", "file(with path) wich will be encrypted")
	mode := flag.String("mode", "ECB", "mode which will be used. Available are: ECB")

	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Error: input file required")
		return
	}

	if *outputFile == "" {
		fmt.Println("Error: output file required")
		return
	}

	key := "0E329232EA6D0D73"

	//fmt.Println(des.EncryptMessage("Your lips are smoother than vaseline\r\n", key))
	//fmt.Println(des.DecryptMessage("c0999fdde378d7ed727da00bca5a84ee47f269a4d6438190d9d52f78f5358499828ac9b453e0e653", key))
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

	inputStats, _ := os.Stat(*inputFile)

	if *decrypt {
		if des.ModDecrypt[*mode] == nil {
			w.Close()
			fmt.Println("Error: unkown mode")
			return
		}

		sizeBytes := make([]byte, 8)

		_, err := r.Read(sizeBytes)

		if err != nil {
			fmt.Println("Error: reading size!")
			w.Close()
			return
		}

		size := binary.BigEndian.Uint64(sizeBytes)

		err = des.ModDecrypt[*mode](size, r, w, key)

		w.Close()
		if err != nil {
			os.Remove(*outputFile)
		}
	} else {
		if des.ModEncrypt[*mode] == nil {
			w.Close()
			fmt.Println("Error: unkown mode")
			return
		}
		size := make([]byte, 8)

		binary.BigEndian.PutUint64(size, uint64(inputStats.Size()))

		w.Write(size)

		err := des.ModEncrypt[*mode](r, w, key)

		w.Close()

		if err != nil {
			os.Remove(*outputFile)
		}
	}
}
