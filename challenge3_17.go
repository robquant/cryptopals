package main

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/robquant/cryptopals/pkg/tools"
)

var key, iv []byte

const bs = 16

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
	key = make([]byte, 16)
	rand.Read(key)
	iv = make([]byte, 16)
	rand.Read(iv)
}

func first(in string) []byte {
	// select at random one of the following 10 strings

	// generate a random AES key (which it should save for all future encryptions)

	// pad the string out to the 16-byte AES block size

	// CBC-encrypt it under that key
	// return the ciphertext and IV.

	return tools.EncryptAesCBC([]byte(in), key, iv)
}

func second(civ, ciphertext []byte) bool {

	// decrypt the ciphertext produced by the first function
	_, err := tools.DecryptAesCBC(ciphertext, key, civ)
	// check its padding
	if err != nil {
		return false
	}
	// return true or false depending on whether the padding is valid.
	return true
}

func findPadding(ciphertext []byte) int {
	startIndex := len(ciphertext) - bs

	clone := make([]byte, len(ciphertext))
	copy(clone, ciphertext)

	for i := range clone[startIndex:] {
		clone[i+startIndex-bs] = 255
		if second(clone) == false {
			return len(ciphertext) - (i + startIndex)
		}
	}

	return -1
}
func findLastByte(prevBlock, targetBlock []byte) (byte, error) {

	c_prevBlock := append([]byte{}, prevBlock...)
	c_prevBlock[14] = 0x34
	for c := 0; c < 256; c++ {
		c_prevBlock[len(c_prevBlock)-1] = byte(c)
		fmt.Println(second(c_prevBlock, targetBlock), c)
		if second(c_prevBlock, targetBlock) {
			fmt.Println(findPadding(c_prevBlock, targetBlock))
			return 0x01 ^ byte(c) ^ prevBlock[len(prevBlock)-1], nil
		}
	}

	return 0, errors.New("Erro")
}

func main() {
	s := inputStrings[0]
	fmt.Println("original", s)
	encrypted := first(s)
	civ := append([]byte{}, iv...)
	b, _ := findLastByte(civ, encrypted[0:bs])
	fmt.Println(b)
	// fmt.Println(second(iv, encrypted))

	// ciphertext[15] ^ decrypted[31] = something
	// our_byte ^decrypted[31] = 0x01 (padding valid)

	// decrypted[31] = 0x01 ^ our_byte
	// something (=plaintext[31]) = decrypted[31] ^ ciphertext[15]

	// ciphertext[15] so that 0x02
	// 0x02 ^
	// play with ciphertext[14]
}
