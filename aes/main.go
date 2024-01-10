package main

import (
	"aes/aes"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

func main() {
	decrypt := flag.Bool("d", false, "whether to decrypt or not")
	inputFile := flag.String("in", "", "file(with path) wich will be encrypted")
	outputFile := flag.String("out", "", "file(with path) wich will be encrypted")
	mode := flag.String("mode", "ECB", "mode which will be used. Available are: ECB, CBC, CFB, OFB")
	secret := flag.String("secret", "", "hex secret block for CBC")
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

	if len(*key) != 32 {
		fmt.Println("Error: key should be in hex and be 32 symbols")
		return
	}

	if *mode != "ECB" && (len(*secret) < 32) {
		fmt.Println("Error: secret required for CBC,CFB,OFB")
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

	inputStats, _ := os.Stat(*inputFile)

	if *decrypt {
		sizeBytesDec := make([]byte, 0, 16)

		sizeBuffer := bytes.NewBuffer(sizeBytesDec)

		err = aes.EcbDecrypt(16, r, sizeBuffer, *key)

		if err != nil {
			fmt.Println("Hey")
			w.Close()
			return
		}

		size := binary.BigEndian.Uint64(sizeBytesDec[0:8])

		switch *mode {
		case "ECB":
			err = aes.EcbDecrypt(size, r, w, *key)
		case "CBC":
			err = aes.CbcDecrypt(size, r, w, *key, *secret)
		case "CFB":
			err = aes.CfbDecrypt(size, r, w, *key, *secret)
		case "OFB":
			err = aes.OfbDecrypt(size, r, w, *key, *secret)
		default:
			fmt.Println("Error: unknown mode")
			w.Close()
			return
		}

		w.Close()
		if err != nil {
			os.Remove(*outputFile)
		}
	} else {
		size := make([]byte, 8)

		binary.BigEndian.PutUint64(size, uint64(inputStats.Size()))

		sizeReader := bytes.NewReader(size)

		err := aes.EcbEncrypt(sizeReader, w, *key)

		switch *mode {
		case "ECB":
			err = aes.EcbEncrypt(r, w, *key)
		case "CBC":
			err = aes.CbcEncrypt(r, w, *key, *secret)
		case "CFB":
			err = aes.CfbEncrypt(r, w, *key, *secret)
		case "OFB":
			err = aes.OfbEncrypt(r, w, *key, *secret)
		default:
			fmt.Println("Error: unknown mode")
			w.Close()
			return
		}

		w.Close()

		if err != nil {
			os.Remove(*outputFile)
		}
	}
}
