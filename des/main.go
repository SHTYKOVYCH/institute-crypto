package main

import (
	"bytes"
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

	if len(*key) < 16 {
		fmt.Println("Error: key should be in hex and be at least 16 symbols")
		return
	}

	if *mode != "ECB" && (len(*secret) < 16) {
		fmt.Println("Error: secret required for CBC,CFB,OFB")
		return
	}

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
		sizeBytesDec := make([]byte, 0, 8)

		sizeBuffer := bytes.NewBuffer(sizeBytesDec)

		err = des.EcbDecrypt(8, r, sizeBuffer, *key)

		if err != nil {
			fmt.Println("Hey")
			w.Close()
			return
		}

		size := binary.BigEndian.Uint64(sizeBytesDec[0:8])

		switch *mode {
		case "ECB":
			err = des.EcbDecrypt(size, r, w, *key)
		case "CBC":
			err = des.CbcDecrypt(size, r, w, *key, *secret)
		case "CFB":
			err = des.CfbDecrypt(size, r, w, *key, *secret)
		case "OFB":
			err = des.OfbDecrypt(size, r, w, *key, *secret)
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

		err := des.EcbEncrypt(sizeReader, w, *key)

		//w.Write(size)

		//var err error

		switch *mode {
		case "ECB":
			err = des.EcbEncrypt(r, w, *key)
		case "CBC":
			err = des.CbcEncrypt(r, w, *key, *secret)
		case "CFB":
			err = des.CfbEncrypt(r, w, *key, *secret)
		case "OFB":
			err = des.OfbEncrypt(r, w, *key, *secret)
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
