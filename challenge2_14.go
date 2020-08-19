package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/robquant/cryptopals/pkg/tools"
)

const encoded = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

var key []byte
var plaintext []byte
var randomPrefix []byte

func init() {
	rand.Seed(time.Now().UnixNano())
	key = make([]byte, 16)
	rand.Read(key)
	prefixLen := rand.Intn(100)
	randomPrefix = make([]byte, prefixLen)
	fmt.Printf("Generated random prefix of len %d\n", prefixLen)
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

func crackLastLetterInBlock(blockOffset, padding int, prefix, target []byte, blockSize int) byte {
	attackerString := bytes.Repeat([]byte{65}, padding)
	attackerString = append(attackerString, prefix...)
	attackerString = append(attackerString, 0)
	// We know that target == oracle(prefix + unknown letter)
	// We call oracle with all possible letters in the last position and compare
	// to the target block. If they are identical we found the letter.
	for b := 0; b <= 255; b++ {
		attackerString[len(attackerString)-1] = byte(b)
		enrypted := oracle(attackerString)
		if bytes.Compare(enrypted[blockOffset*blockSize:(blockOffset+1)*blockSize], target) == 0 {
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
	// by feeding it 3 blocksize blocks of repeated "A"'s and look for
	// repetitions in the encrypted output
	var blockSize int = 0
	for bs := 16; bs <= 33; bs++ {
		prefix := bytes.Repeat([]byte{65}, 3*bs)
		encrypted := oracle(prefix)
		nblocks := int(math.Floor(float64(len(encrypted))/float64(bs))) - 1
		for iblock := 0; iblock < nblocks; iblock++ {
			if bytes.Compare(encrypted[bs*iblock:bs*(iblock+1)], encrypted[bs*(iblock+1):bs*(iblock+2)]) == 0 {
				blockSize = bs
				break
			}
		}
		if blockSize > 0 {
			break
		}
	}
	fmt.Printf("Blocksize is %d\n", blockSize)
	if blockSize == 0 {
		fmt.Printf("fail\n")
		os.Exit(1)
	}

	prefix := bytes.Repeat([]byte{65}, blockSize*2)
	var blockStartFound int = -1
	for i := 0; i < blockSize; i++ {
		encrypted := oracle(prefix)
		nblocks := int(math.Floor(float64(len(encrypted))/float64(blockSize))) - 1
		for iblock := 0; iblock < nblocks; iblock++ {
			if bytes.Compare(encrypted[blockSize*iblock:blockSize*(iblock+1)], encrypted[blockSize*(iblock+1):blockSize*(iblock+2)]) == 0 {
				blockStartFound = iblock
				break
			}
		}
		if blockStartFound >= 0 {
			break
		}
		prefix = append(prefix, 65)
	}
	randomPrefixLen := blockSize*(blockStartFound+2) - len(prefix)
	fmt.Printf("randomPrefix: %d\n", randomPrefixLen)

	padding := blockSize - randomPrefixLen%blockSize
	decoded := bytes.Repeat([]byte{65}, blockSize)
	blockOffset := (padding + randomPrefixLen) / blockSize
	for i := 0; i < len(plaintext); i++ {
		blockIndex := blockOffset + i/blockSize // block of plaintext we are cracking
		// We alway make sure the next letter the decode is last in a block
		// and we hae decoded all the letters before this one
		// E.g. to decode the first plaintext letters we prefix with
		// blocksize - 1 "A"s
		prefixLength := blockSize - (i % blockSize) - 1 //
		prefix := bytes.Repeat([]byte{65}, padding+prefixLength)
		encrypted := oracle(prefix)
		// Cut out the block were the letter we are trying to crack is last in the block
		targetBlock := encrypted[blockIndex*blockSize : (blockIndex+1)*blockSize]
		// decoded[len(decoded)-blockSize+1:] are the letters before the target letter that
		// we have already decoded (or chosen)
		b := crackLastLetterInBlock(blockOffset, padding, decoded[len(decoded)-blockSize+1:], targetBlock, blockSize)
		decoded = append(decoded, b)
	}
	fmt.Println(string(decoded[blockSize:]))
	fmt.Printf("Runtime: %v \n", time.Since(start))
}
