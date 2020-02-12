package tools

import (
	"errors"
)

func Xor(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, errors.New("Buffers should have same length")
	}
	res := make([]byte, len(b1))
	for i := 0; i < len(b1); i++ {
		res[i] = b1[i] ^ b2[i]
	}
	return res, nil
}

func XorSingleLetter(input []byte, key byte) []byte {
	res := make([]byte, 0)
	for _, b := range input {
		res = append(res, b^key)
	}
	return res
}

func RepeatedKeyXor(input, key []byte) []byte {
	keyLength := len(key)
	result := make([]byte, len(input))
	for i, b := range input {
		result[i] = b ^ key[i%keyLength]
	}
	return result
}
