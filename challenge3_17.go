package main

import (
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

func second(ciphertext []byte) bool {

	// decrypt the ciphertext produced by the first function
	_, err := tools.DecryptAesCBC(ciphertext, key, iv)
	// check its padding
	if err != nil {
		return false
	}
	// return true or false depending on whether the padding is valid.
	return true
}

func main() {
	s := inputStrings[rand.Int31n(int32(len(inputStrings)))]
	encrypted := first(s)
	fmt.Println(second(encrypted))

	// ciphertext[15] ^ decrypted[31] = something
	// our_byte ^decrypted[31] = 0x01 (padding valid)

	// decrypted[31] = 0x01 ^ our_byte
	// something (=plaintext[31]) = decrypted[31] ^ ciphertext[15]

	// ciphertext[15] so that 0x02
	// 0x02 ^
	// play with ciphertext[14]
}
