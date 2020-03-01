package main

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/robquant/cryptopals/pkg/tools"
)

func randomBytes(n int32) []byte {
	res := make([]byte, n)
	rand.Read(res)
	return res
}

func encryptionOracle(input []byte) []byte {
	padded := make([]byte, 0)
	padded = append(padded, randomBytes(5+rand.Int31n(6))...)
	padded = append(padded, input...)
	padded = append(padded, randomBytes(5+rand.Int31n(6))...)
	key := randomBytes(16)
	if rand.Float64() < 0.5 {
		fmt.Println("Choosing ECB")
		return tools.EncryptAesECB(padded, key)
	} else {
		fmt.Println("Choosing CBC")
		iv := randomBytes(16)
		return tools.EncryptAesCBC(padded, key, iv)
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	input := strings.Repeat("A", 43)
	encrypted := encryptionOracle([]byte(input))
	if tools.CountSameBlocks(encrypted, 16) > 0 {
		fmt.Println("Detected ECB")
	} else {
		fmt.Println("Detected CBC")
	}
}
