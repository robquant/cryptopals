package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/robquant/cryptopals/pkg/tools"
)

const encoded = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

var key []byte
var plaintext []byte

func init() {
	key = make([]byte, 16)
	rand.Read(key)
}

func oracle(prefix []byte) []byte {
	combined := make([]byte, 0)
	combined = append(combined, prefix...)
	combined = append(combined, plaintext...)
	return tools.EncryptAesECB(combined, key)
}

func crackLastLetterInBlock(prefix, target []byte, blockSize int) byte {
	attackerString := make([]byte, blockSize)
	copy(attackerString, prefix)
	for b := 0; b <= 255; b++ {
		attackerString[blockSize-1] = byte(b)
		enrypted := oracle(attackerString)
		if bytes.Compare(enrypted[:blockSize], target) == 0 {
			return byte(b)
		}
	}
	return 0
}

func main() {
	start := time.Now()
	var err error
	plaintext, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Fatal(err)
	}
	var blockSize int
	for bs := 1; bs <= 33; bs++ {
		prefix := bytes.Repeat([]byte{65}, 2*bs)
		encrypted := oracle(prefix)
		if bytes.Compare(encrypted[:bs], encrypted[bs:2*bs]) == 0 {
			blockSize = bs
			break
		}
	}
	fmt.Printf("Blocksize is %d\n", blockSize)
	decoded := bytes.Repeat([]byte{65}, blockSize)
	for i := 0; i < len(plaintext); i++ {
		blockIndex := i / blockSize
		prefixLength := blockSize - (i % blockSize) - 1
		prefix := bytes.Repeat([]byte{65}, prefixLength)
		encrypted := oracle(prefix)
		targetBlock := encrypted[blockIndex*blockSize : (blockIndex+1)*blockSize]
		b := crackLastLetterInBlock(decoded[len(decoded)-blockSize+1:], targetBlock, blockSize)
		decoded = append(decoded, b)
	}
	fmt.Println(string(decoded[blockSize:]))
	fmt.Printf("Runtime: %v \n", time.Since(start))
}
