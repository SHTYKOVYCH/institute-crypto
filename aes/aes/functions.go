package aes

import (
	"encoding/hex"
	"io"
)

func ByteArrayXOrg(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("Different length of arrays!")
	}

	newWord := make([]byte, len(a))

	for i := 0; i < len(a); i += 1 {
		newWord[i] = a[i] ^ b[i]
	}

	return newWord
}

func RotWord(word []byte) []byte {
	newWord := make([]byte, len(word))

	for i := 0; i < len(newWord)-1; i += 1 {
		newWord[i] = word[i+1]
	}

	newWord[len(word)-1] = word[0]

	return newWord
}

func SubWord(word []byte) []byte {
	newWord := make([]byte, len(word))

	for i := range word {
		newWord[i] = S[word[i]]
	}

	return newWord
}

func SubWordReverse(word []byte) []byte {
	newWord := make([]byte, len(word))

	for i := range word {
		newWord[i] = SInv[word[i]]
	}

	return newWord
}

func ApplyRCon(word []byte, index int) []byte {
	return ByteArrayXOrg(word, Rcon[index])
}

func ShiftRows(word []byte) []byte {
	newWord := make([]byte, len(word))

	for i := 0; i < 4; i += 1 {
		newWord[i*4] = word[i*4]
		newWord[i*4+1] = word[((i+1)*4)%16+1]
		newWord[i*4+2] = word[((i+2)*4)%16+2]
		newWord[i*4+3] = word[((i+3)*4)%16+3]
	}

	return newWord
}

func ShiftRowsReverse(word []byte) []byte {
	newWord := make([]byte, len(word))

	for i := 0; i < 4; i += 1 {
		newWord[i*4] = word[i*4]
		newWord[i*4+1] = word[((i+3)*4)%16+1]
		newWord[i*4+2] = word[((i+2)*4)%16+2]
		newWord[i*4+3] = word[((i+1)*4)%16+3]
	}

	return newWord
}

func GaluaMult2(a byte) byte {
	result := a << 1

	if a&0x80 == 0 {
		return result
	}

	return result ^ 0x1b
}

func GaluaMultByte(a byte, b byte) byte {
	result := byte(0)
	for i := 0; i < 8; i += 1 {
		if b&1 == 1 {
			subRes := a
			for j := 0; j < i; j += 1 {
				subRes = GaluaMult2(subRes)
			}
			result ^= subRes
		}
		b >>= 1
	}

	return result
}

func MixColumns(word []byte) []byte {
	ret := make([]byte, len(word))

	for i := 0; i < 4; i += 1 {
		for j := 0; j < 4; j += 1 {
			ret[i*4+j] = GaluaMultByte(C[j*4], word[i*4]) ^ GaluaMultByte(C[j*4+1], word[i*4+1]) ^ GaluaMultByte(C[j*4+2], word[i*4+2]) ^ GaluaMultByte(C[j*4+3], word[i*4+3])
		}
	}

	return ret
}

func MixColumnsInv(word []byte) []byte {
	ret := make([]byte, len(word))

	for i := 0; i < 4; i += 1 {
		for j := 0; j < 4; j += 1 {
			ret[i*4+j] = GaluaMultByte(CInv[j*4], word[i*4]) ^ GaluaMultByte(CInv[j*4+1], word[i*4+1]) ^ GaluaMultByte(CInv[j*4+2], word[i*4+2]) ^ GaluaMultByte(CInv[j*4+3], word[i*4+3])
		}
	}

	return ret
}

func GetRoundKeys(keyStr string) [][]byte {
	if len(keyStr) != 32 {
		panic("Key should be 16 bytes!")
	}

	key, _ := hex.DecodeString(keyStr)

	roundKeys := make([][]byte, 11)

	roundKeys[0] = key

	for i := 1; i < len(roundKeys); i += 1 {
		roundKeys[i] = make([]byte, 0)

		firstVal := roundKeys[i-1][12:]

		roundKeys[i] = append(roundKeys[i], ByteArrayXOrg(ApplyRCon(SubWord(RotWord(firstVal)), i), roundKeys[i-1][:4])...)
		roundKeys[i] = append(roundKeys[i], ByteArrayXOrg(roundKeys[i][0:4], roundKeys[i-1][4:8])...)
		roundKeys[i] = append(roundKeys[i], ByteArrayXOrg(roundKeys[i][4:8], roundKeys[i-1][8:12])...)
		roundKeys[i] = append(roundKeys[i], ByteArrayXOrg(roundKeys[i][8:12], roundKeys[i-1][12:])...)
	}

	return roundKeys
}

func EcbEncrypt(reader io.Reader, writer io.Writer, key string) error {
	roundKeys := GetRoundKeys(key)
	msgBytes := make([]byte, len(roundKeys[0]))

	for {
		for i := 0; i < len(msgBytes); i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		_, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		outMsg := ByteArrayXOrg(msgBytes, roundKeys[0])

		for i := 1; i < 10; i += 1 {
			outMsg = ByteArrayXOrg(MixColumns(ShiftRows(SubWord(outMsg))), roundKeys[i])
		}

		outMsg = ByteArrayXOrg(ShiftRows(SubWord(outMsg)), roundKeys[10])

		_, err = writer.Write(outMsg)

		if err != nil {
			return err
		}
	}

	return nil
}

func EcbDecrypt(size uint64, reader io.Reader, writer io.Writer, key string) error {
	roundKeys := GetRoundKeys(key)
	msgBytes := make([]byte, len(roundKeys[0]))

	totalRead := 0

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

		totalRead += n

		outMsg := SubWordReverse(ShiftRowsReverse(ByteArrayXOrg(msgBytes, roundKeys[10])))
		for i := 9; i > 0; i -= 1 {
			outMsg = SubWordReverse(ShiftRowsReverse(MixColumnsInv(ByteArrayXOrg(outMsg, roundKeys[i]))))
		}

		outMsg = ByteArrayXOrg(outMsg, roundKeys[0])
		if uint64(totalRead) > size {
			msgBytes = msgBytes[:16-(uint64(totalRead)-size)]
		}

		_, err = writer.Write(outMsg)

		if err != nil {
			return err
		}

		if uint64(totalRead) >= size {
			break
		}
	}

	return nil
}

func CbcEncrypt(reader io.Reader, writer io.Writer, key string, secret string) error {
	roundKeys := GetRoundKeys(key)
	msgBytes := make([]byte, len(roundKeys[0]))
	lastMsgBytes, _ := hex.DecodeString(secret)

	for {
		for i := 0; i < len(msgBytes); i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		_, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}
		outMsg := ByteArrayXOrg(msgBytes, lastMsgBytes)

		outMsg = ByteArrayXOrg(outMsg, roundKeys[0])

		for i := 1; i < 10; i += 1 {
			outMsg = ByteArrayXOrg(MixColumns(ShiftRows(SubWord(outMsg))), roundKeys[i])
		}

		outMsg = ByteArrayXOrg(ShiftRows(SubWord(outMsg)), roundKeys[10])

		for i := 0; i < 16; i += 1 {
			lastMsgBytes[i] = outMsg[i]
		}

		_, err = writer.Write(outMsg)

		if err != nil {
			return err
		}
	}

	return nil
}

func CbcDecrypt(size uint64, reader io.Reader, writer io.Writer, key string, secret string) error {
	roundKeys := GetRoundKeys(key)
	msgBytes := make([]byte, len(roundKeys[0]))
	lastMsgBytes, _ := hex.DecodeString(secret)

	totalRead := 0

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

		totalRead += n

		outMsg := SubWordReverse(ShiftRowsReverse(ByteArrayXOrg(msgBytes, roundKeys[10])))
		for i := 9; i > 0; i -= 1 {
			outMsg = SubWordReverse(ShiftRowsReverse(MixColumnsInv(ByteArrayXOrg(outMsg, roundKeys[i]))))
		}

		outMsg = ByteArrayXOrg(outMsg, roundKeys[0])

		outMsg = ByteArrayXOrg(outMsg, lastMsgBytes)
		for i := 0; i < 16; i += 1 {
			lastMsgBytes[i] = msgBytes[i]
		}
		if uint64(totalRead) > size {
			outMsg = outMsg[:16-(uint64(totalRead)-size)]
		}

		_, err = writer.Write(outMsg)

		if err != nil {
			return err
		}

		if uint64(totalRead) >= size {
			break
		}
	}

	return nil
}

func CfbEncrypt(reader io.Reader, writer io.Writer, key string, secret string) error {
	roundKeys := GetRoundKeys(key)
	msgBytes := make([]byte, len(roundKeys[0]))
	lastMsgBytes, _ := hex.DecodeString(secret)

	for {
		for i := 0; i < len(msgBytes); i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		_, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		outMsg := ByteArrayXOrg(lastMsgBytes, roundKeys[0])

		for i := 1; i < 10; i += 1 {
			outMsg = ByteArrayXOrg(MixColumns(ShiftRows(SubWord(outMsg))), roundKeys[i])
		}

		outMsg = ByteArrayXOrg(ShiftRows(SubWord(outMsg)), roundKeys[10])

		outMsg = ByteArrayXOrg(outMsg, msgBytes)

		for i := 0; i < 16; i += 1 {
			lastMsgBytes[i] = outMsg[i]
		}

		_, err = writer.Write(outMsg)

		if err != nil {
			return err
		}
	}

	return nil
}

func CfbDecrypt(size uint64, reader io.Reader, writer io.Writer, key string, secret string) error {
	roundKeys := GetRoundKeys(key)
	msgBytes := make([]byte, len(roundKeys[0]))
	lastMsgBytes, _ := hex.DecodeString(secret)

	totalRead := 0

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

		totalRead += n

		outMsg := ByteArrayXOrg(lastMsgBytes, roundKeys[0])

		for i := 1; i < 10; i += 1 {
			outMsg = ByteArrayXOrg(MixColumns(ShiftRows(SubWord(outMsg))), roundKeys[i])
		}

		outMsg = ByteArrayXOrg(ShiftRows(SubWord(outMsg)), roundKeys[10])

		outMsg = ByteArrayXOrg(outMsg, msgBytes)

		for i := 0; i < 16; i += 1 {
			lastMsgBytes[i] = msgBytes[i]
		}
		if uint64(totalRead) > size {
			outMsg = outMsg[:16-(uint64(totalRead)-size)]
		}

		_, err = writer.Write(outMsg)

		if err != nil {
			return err
		}

		if uint64(totalRead) >= size {
			break
		}
	}

	return nil
}

func OfbEncrypt(reader io.Reader, writer io.Writer, key string, secret string) error {
	roundKeys := GetRoundKeys(key)
	msgBytes := make([]byte, len(roundKeys[0]))
	lastMsgBytes, _ := hex.DecodeString(secret)

	for {
		for i := 0; i < len(msgBytes); i += 1 {
			msgBytes[i] ^= msgBytes[i]
		}

		_, err := reader.Read(msgBytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		outMsg := ByteArrayXOrg(lastMsgBytes, roundKeys[0])

		for i := 1; i < 10; i += 1 {
			outMsg = ByteArrayXOrg(MixColumns(ShiftRows(SubWord(outMsg))), roundKeys[i])
		}

		outMsg = ByteArrayXOrg(ShiftRows(SubWord(outMsg)), roundKeys[10])

		for i := 0; i < 16; i += 1 {
			lastMsgBytes[i] = outMsg[i]
		}

		outMsg = ByteArrayXOrg(outMsg, msgBytes)

		_, err = writer.Write(outMsg)

		if err != nil {
			return err
		}
	}

	return nil
}

func OfbDecrypt(size uint64, reader io.Reader, writer io.Writer, key string, secret string) error {
	roundKeys := GetRoundKeys(key)
	msgBytes := make([]byte, len(roundKeys[0]))
	lastMsgBytes, _ := hex.DecodeString(secret)

	totalRead := 0

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

		totalRead += n

		outMsg := ByteArrayXOrg(lastMsgBytes, roundKeys[0])

		for i := 1; i < 10; i += 1 {
			outMsg = ByteArrayXOrg(MixColumns(ShiftRows(SubWord(outMsg))), roundKeys[i])
		}

		outMsg = ByteArrayXOrg(ShiftRows(SubWord(outMsg)), roundKeys[10])

		for i := 0; i < 16; i += 1 {
			lastMsgBytes[i] = outMsg[i]
		}

		outMsg = ByteArrayXOrg(outMsg, msgBytes)

		if uint64(totalRead) > size {
			outMsg = outMsg[:16-(uint64(totalRead)-size)]
		}

		_, err = writer.Write(outMsg)

		if err != nil {
			return err
		}

		if uint64(totalRead) >= size {
			break
		}
	}

	return nil
}
