package main

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/robquant/cryptopals/pkg/tools"
)

var KEY, IV []byte

const BS = 16

var inputStrings = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

func init() {
	rand.Seed(time.Now().UnixNano())
	KEY = make([]byte, BS)
	rand.Read(KEY)
	IV = make([]byte, BS)
	rand.Read(IV)
}

func first(in string) []byte {
	// select at random one of the following 10 strings

	// generate a random AES key (which it should save for all future encryptions)

	// pad the string out to the 16-byte AES block size

	// CBC-encrypt it under that key
	// return the ciphertext and IV.

	return tools.EncryptAesCBC([]byte(in), KEY, IV)
}

func second(iv, ciphertext []byte) bool {

	// decrypt the ciphertext produced by the first function
	_, err := tools.DecryptAesCBC(ciphertext, KEY, iv)
	// check its padding
	if err != nil {
		return false
	}
	// return true or false depending on whether the padding is valid.
	return true
}

// func findPadding(iv, block []byte) int {
// 	startIndex := len(ciphertext) - BS

// 	clone := make([]byte, len(ciphertext))
// 	copy(clone, ciphertext)

// 	for i := range clone[startIndex:] {
// 		clone[i+startIndex-BS] = 255
// 		if second(clone) == false {
// 			return len(ciphertext) - (i + startIndex)
// 		}
// 	}
// 	return -1
// }

func findLastByte(prevBlock, targetBlock []byte) (byte, error) {

	copyPrevBlock := append([]byte{}, prevBlock...)
	for c := 0; c < 256; c++ {
		copyPrevBlock[len(copyPrevBlock)-1] = byte(c)
		if second(copyPrevBlock, targetBlock) {
			// fmt.Println(findPadding(copyPrevBlock, targetBlock))
			return 0x01 ^ byte(c) ^ prevBlock[len(prevBlock)-1], nil
		}
	}

	return 0, errors.New("Error")
}

func main() {
	s := inputStrings[rand.Intn(len(inputStrings))]
	fmt.Println("original", s)
	encrypted := first(s)
	b, _ := findLastByte(IV, encrypted[0:BS])
	fmt.Printf("Should be: %s, got %s\n", s[BS-1:BS], string([]byte{b}))
	// fmt.Println(second(iv, encrypted))

	// ciphertext[15] ^ decrypted[31] = something
	// our_byte ^decrypted[31] = 0x01 (padding valid)

	// decrypted[31] = 0x01 ^ our_byte
	// something (=plaintext[31]) = decrypted[31] ^ ciphertext[15]

	// ciphertext[15] so that 0x02
	// 0x02 ^
	// play with ciphertext[14]
}
