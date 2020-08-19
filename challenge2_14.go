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
var randomPrefix []byte

func init() {
	key = make([]byte, 16)
	rand.Read(key)
	prefixLen := rand.Intn(100)
	randomPrefix = make([]byte, prefixLen)
	rand.Read(randomPrefix)
}

// Create a combined string of our chosen prefix and the
// unknown plaintext. Enrypt with AES in ECB mode.
func oracle(prefix []byte) []byte {
	combined := make([]byte, 0)
	combined = append(combined, randomPrefix...)
	combined = append(combined, prefix...)
	combined = append(combined, plaintext...)
	return tools.EncryptAesECB(combined, key)
}

//
func crackLastLetterInBlock(prefix, target []byte, blockSize int) byte {
	attackerString := make([]byte, blockSize)
	copy(attackerString, prefix)
	// We know that target == oracle(prefix + unknown letter)
	// We call oracle with all possible letters in the last position and compare
	// to the target block. If they are identical we found the letter.
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
	// Figure out the block size of the encryption algorithm
	// by feeding it 2 blocksize blocks of repeated "A"'s and look for
	// repetitions in the encrypted output
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
		blockIndex := i / blockSize // block of plaintext we are cracking
		// We alway make sure the next letter the decode is last in a block
		// and we hae decoded all the letters before this one
		// E.g. to decode the first plaintext letters we prefix with
		// blocksize - 1 "A"s
		prefixLength := blockSize - (i % blockSize) - 1 //
		prefix := bytes.Repeat([]byte{65}, prefixLength)
		encrypted := oracle(prefix)
		// Cut out the block were the letter we are trying to crack is last in the block
		targetBlock := encrypted[blockIndex*blockSize : (blockIndex+1)*blockSize]
		// decoded[len(decoded)-blockSize+1:] are the letters before the target letter that
		// we have already decoded (or chosen)
		b := crackLastLetterInBlock(decoded[len(decoded)-blockSize+1:], targetBlock, blockSize)
		decoded = append(decoded, b)
	}
	fmt.Println(string(decoded[blockSize:]))
	fmt.Printf("Runtime: %v \n", time.Since(start))
}
