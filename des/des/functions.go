package des

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"strconv"
)

func ReorderWithTable(chunk uint64, table [][]uint64) uint64 {
	var reworked uint64 = 0
	for j := 0; j < len(table); j += 1 {
		bit := chunk & table[j][1]
		shift := int64(j) - int64(table[j][0]) + 1

		if shift < 0 {
			bit = bit << -shift
		} else {
			bit = bit >> shift
		}

		reworked = reworked | bit
	}

	return reworked
}

// GetRoundKeys Func returns array of round keys
// INPUT ARGUMENTS:
// key	string	hex string with 8bytes of data
func GetRoundKeys(keyStr string) []uint64 {
	if len(keyStr) != 16 {
		panic("Key should be 8 bytes!")
	}

	key, _ := strconv.ParseUint(keyStr, 16, 64)

	reworkedKey := ReorderWithTable(key, PC1)

	roundKeys := make([]uint64, 16)
	cds := make([]uint64, 17)

	cds[0] = reworkedKey

	roundKeys[0] = reworkedKey

	for i := 1; i < 17; i += 1 {
		c := cds[i-1] & 0xfffffff000000000
		d := cds[i-1] & 0x0000000fffffff00
		for j := 0; j < NumOfShitfts[i]; j += 1 {
			c = (c << 1) | (c & 0x8000000000000000 >> 27)
			d = (d<<1)&0x0000000fffffff00 | ((d & 0x800000000) >> 27)
		}
		cds[i] = c | d
		roundKeys[i-1] = ReorderWithTable(c|d, PC2)
	}

	return roundKeys
}

func FeistelNet(messg uint64, roundKeys []uint64) uint64 {
	lrs := make([][]uint64, 17)

	lrs[0] = make([]uint64, 2)
	lrs[0][0] = messg & 0xffffffff00000000
	lrs[0][1] = (messg & 0xffffffffff) << 32

	for i := 1; i < 17; i += 1 {
		lrs[i] = make([]uint64, 2)
		lrs[i][0] = lrs[i-1][1]

		e := ReorderWithTable(lrs[i-1][1], E)

		ek := e ^ roundKeys[i-1]

		startMask := uint64(0xfc00000000000000)

		outE := uint64(0)
		for k := 0; k < 8; k += 1 {
			outE <<= 4
			ekI := (ek & startMask) >> (58 - k*6)
			tableIndex := ((ekI & 0x20) >> 4) | (ekI & 0x1)
			rowIndex := (ekI & 0x1E) >> 1

			outE |= uint64(S[k][tableIndex*16+rowIndex])
			startMask >>= 6
		}
		outE <<= 32

		newE := ReorderWithTable(outE, P)

		lrs[i][1] = lrs[i-1][0] ^ newE
	}

	return lrs[16][1] | lrs[16][0]>>32
}

func ReverseFeistelNet(messg uint64, roundKeys []uint64) uint64 {
	lrs := make([][]uint64, 17)

	lrs[0] = make([]uint64, 2)
	lrs[0][0] = messg & 0xffffffff00000000
	lrs[0][1] = (messg & 0xffffffffff) << 32

	for i := 1; i < 17; i += 1 {
		lrs[i] = make([]uint64, 2)
		lrs[i][0] = lrs[i-1][1]

		e := ReorderWithTable(lrs[i-1][1], E)

		ek := e ^ roundKeys[16-i]

		startMask := uint64(0xfc00000000000000)

		outE := uint64(0)
		for k := 0; k < 8; k += 1 {
			outE <<= 4
			ekI := (ek & startMask) >> (58 - k*6)
			tableIndex := ((ekI & 0x20) >> 4) | (ekI & 0x1)
			rowIndex := (ekI & 0x1E) >> 1

			outE |= uint64(S[k][tableIndex*16+rowIndex])
			startMask >>= 6
		}
		outE <<= 32

		newE := ReorderWithTable(outE, P)

		lrs[i][1] = lrs[i-1][0] ^ newE
	}

	return lrs[16][1] | lrs[16][0]>>32
}

func EncryptMessage(msg string, key string) string {
	msgBytes := []byte(msg)

	msgChunksLen := len(msgBytes) / 8
	if len(msgBytes)%8 > 0 {
		msgChunksLen += 1
	}

	msgChunks := make([][]byte, msgChunksLen)

	for i := 0; i < msgChunksLen; i += 1 {
		msgChunks[i] = []byte{}

		if i+1 == msgChunksLen {
			msgChunks[i] = []byte(msgBytes[i*8:])
		} else {
			msgChunks[i] = []byte(msgBytes[i*8 : (i+1)*8])
		}
		if len(msgChunks[i]) < 8 {
			for j := len(msgChunks[i]); j < 8; j += 1 {
				msgChunks[i] = append(msgChunks[i], 0)
			}
		}
	}
	msgBlocks := make([]uint64, msgChunksLen)

	for i := 0; i < msgChunksLen; i += 1 {
		msgBlocks[i] = binary.BigEndian.Uint64(msgChunks[i])
	}

	outStr := ""
	roundKeys := GetRoundKeys(key)

	for i := 0; i < msgChunksLen; i += 1 {
		outMSG := ReorderWithTable(FeistelNet(ReorderWithTable(msgBlocks[i], IP), roundKeys), RP)

		outStr += strconv.FormatUint(outMSG, 16)
	}

	return outStr
}

func DecryptMessage(msg string, key string) string {
	msgBytes := []byte(msg)

	msgChunksLen := len(msgBytes) / 16
	if len(msgBytes)%16 != 0 {
		panic("Broken message")
	}

	msgChunks := make([][]byte, msgChunksLen)

	for i := 0; i < msgChunksLen; i += 1 {
		msgChunks[i] = []byte{}

		if i+1 == msgChunksLen {
			msgChunks[i] = msgBytes[i*16:]
		} else {
			msgChunks[i] = msgBytes[i*16 : (i+1)*16]
		}
	}

	msgBlocks := make([]uint64, msgChunksLen)

	for i := 0; i < msgChunksLen; i += 1 {
		msgBlocks[i], _ = strconv.ParseUint(string(msgChunks[i]), 16, 64)
	}

	outStr := ""
	roundKeys := GetRoundKeys(key)

	for i := 0; i < msgChunksLen; i += 1 {
		newMessg := ReorderWithTable(msgBlocks[i], IP)
		preOutMSG := ReverseFeistelNet(newMessg, roundKeys)
		outMSG := ReorderWithTable(preOutMSG, RP)

		str, _ := hex.DecodeString(strconv.FormatUint(outMSG, 16))

		outStr += string(str)
	}

	return outStr
}

func EcbEncrypt(reader io.Reader, writer io.Writer, key string) error {
	msgBytes := make([]byte, 8)
	roundKeys := GetRoundKeys(key)

	for {
		for i := 0; i < 8; i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		_, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		msgBlock := binary.BigEndian.Uint64(msgBytes)

		outMSG := ReorderWithTable(FeistelNet(ReorderWithTable(msgBlock, IP), roundKeys), RP)

		binary.BigEndian.PutUint64(msgBytes, outMSG)

		_, err = writer.Write(msgBytes)

		if err != nil {
			return err
		}
	}
	return nil
}

func EcbDecrypt(size uint64, reader io.Reader, writer io.Writer, key string) error {
	msgBytes := make([]byte, 8)
	roundKeys := GetRoundKeys(key)

	var totalRead uint64 = 0

	for {
		for i := 0; i < len(msgBytes); i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		n, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		totalRead += uint64(n)

		msgBlock := binary.BigEndian.Uint64(msgBytes)

		outMSG := ReorderWithTable(ReverseFeistelNet(ReorderWithTable(msgBlock, IP), roundKeys), RP)

		binary.BigEndian.PutUint64(msgBytes, outMSG)

		if totalRead > size {
			msgBytes = msgBytes[:8-(totalRead-size)]
		}

		_, err = writer.Write(msgBytes)

		if err != nil {
			return err
		}
	}
	return nil
}

func CbcEncrypt(reader io.Reader, writer io.Writer, key string, secret string) error {
	msgBytes := make([]byte, 8)
	roundKeys := GetRoundKeys(key)
	lastMsgBytes, _ := strconv.ParseUint(secret, 16, 64)

	for {
		for i := 0; i < 8; i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		_, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		msgBlock := binary.BigEndian.Uint64(msgBytes)

		outMSG := ReorderWithTable(FeistelNet(ReorderWithTable(msgBlock^lastMsgBytes, IP), roundKeys), RP)

		binary.BigEndian.PutUint64(msgBytes, outMSG)

		_, err = writer.Write(msgBytes)

		if err != nil {
			return err
		}

		lastMsgBytes = outMSG
	}
	return nil
}

func CbcDecrypt(size uint64, reader io.Reader, writer io.Writer, key string, secret string) error {
	msgBytes := make([]byte, 8)
	roundKeys := GetRoundKeys(key)
	lastMsgBytes, _ := strconv.ParseUint(secret, 16, 64)

	var totalRead uint64 = 0

	for {
		for i := 0; i < len(msgBytes); i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		n, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		totalRead += uint64(n)

		msgBlock := binary.BigEndian.Uint64(msgBytes)

		outMSG := ReorderWithTable(ReverseFeistelNet(ReorderWithTable(msgBlock, IP), roundKeys), RP) ^ lastMsgBytes
		lastMsgBytes = msgBlock

		binary.BigEndian.PutUint64(msgBytes, outMSG)

		if totalRead > size {
			msgBytes = msgBytes[:8-(totalRead-size)]
		}

		_, err = writer.Write(msgBytes)

		if err != nil {
			return err
		}

	}
	return nil
}

func CfbEncrypt(reader io.Reader, writer io.Writer, key string, secret string) error {
	msgBytes := make([]byte, 8)
	roundKeys := GetRoundKeys(key)
	lastMsgBytes, _ := strconv.ParseUint(secret, 16, 64)

	for {
		for i := 0; i < 8; i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		_, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		msgBlock := binary.BigEndian.Uint64(msgBytes)

		outMSG := ReorderWithTable(FeistelNet(ReorderWithTable(lastMsgBytes, IP), roundKeys), RP) ^ msgBlock

		binary.BigEndian.PutUint64(msgBytes, outMSG)

		_, err = writer.Write(msgBytes)

		if err != nil {
			return err
		}

		lastMsgBytes = outMSG
	}
	return nil
}

func CfbDecrypt(size uint64, reader io.Reader, writer io.Writer, key string, secret string) error {
	msgBytes := make([]byte, 8)
	roundKeys := GetRoundKeys(key)
	lastMsgBytes, _ := strconv.ParseUint(secret, 16, 64)

	var totalRead uint64 = 0

	for {
		for i := 0; i < len(msgBytes); i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		n, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		totalRead += uint64(n)

		msgBlock := binary.BigEndian.Uint64(msgBytes)

		outMSG := ReorderWithTable(FeistelNet(ReorderWithTable(lastMsgBytes, IP), roundKeys), RP) ^ msgBlock
		lastMsgBytes = msgBlock

		binary.BigEndian.PutUint64(msgBytes, outMSG)

		if totalRead > size {
			msgBytes = msgBytes[:8-(totalRead-size)]
		}

		_, err = writer.Write(msgBytes)

		if err != nil {
			return err
		}

	}
	return nil
}

func OfbEncrypt(reader io.Reader, writer io.Writer, key string, secret string) error {
	msgBytes := make([]byte, 8)
	roundKeys := GetRoundKeys(key)
	lastMsgBytes, _ := strconv.ParseUint(secret, 16, 64)

	for {
		for i := 0; i < 8; i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		_, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		msgBlock := binary.BigEndian.Uint64(msgBytes)

		outMSG := ReorderWithTable(FeistelNet(ReorderWithTable(lastMsgBytes, IP), roundKeys), RP)
		lastMsgBytes = outMSG
		outMSG ^= msgBlock

		binary.BigEndian.PutUint64(msgBytes, outMSG)

		_, err = writer.Write(msgBytes)

		if err != nil {
			return err
		}
	}
	return nil
}

func OfbDecrypt(size uint64, reader io.Reader, writer io.Writer, key string, secret string) error {
	msgBytes := make([]byte, 8)
	roundKeys := GetRoundKeys(key)
	lastMsgBytes, _ := strconv.ParseUint(secret, 16, 64)

	var totalRead uint64 = 0

	for {
		for i := 0; i < len(msgBytes); i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		n, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		totalRead += uint64(n)

		msgBlock := binary.BigEndian.Uint64(msgBytes)

		outMSG := ReorderWithTable(FeistelNet(ReorderWithTable(lastMsgBytes, IP), roundKeys), RP)
		lastMsgBytes = outMSG
		outMSG ^= msgBlock

		binary.BigEndian.PutUint64(msgBytes, outMSG)

		if totalRead > size {
			msgBytes = msgBytes[:8-(totalRead-size)]
		}

		_, err = writer.Write(msgBytes)

		if err != nil {
			return err
		}

	}
	return nil
}
