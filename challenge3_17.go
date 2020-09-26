package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"

	"github.com/robquant/cryptopals/pkg/tools"
)

var KEY []byte

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

}

func first(in string) ([]byte, []byte) {
	// select at random one of the following 10 strings

	// generate a random AES key (which it should save for all future encryptions)

	// pad the string out to the 16-byte AES block size

	// CBC-encrypt it under that key
	// return the ciphertext and IV.
	var iv []byte = make([]byte, BS)
	rand.Read(iv)
	return iv, tools.EncryptAesCBC([]byte(in), KEY, iv)
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

func findPadding(iv, block []byte) byte {
	cloneBlock := append([]byte{}, block...)
	cloneIv := append([]byte{}, iv...)

	if second(cloneIv, cloneBlock) == false {
		return 0
	}

	for i := 0; i < BS; i++ {
		cloneIv[i] ^= 255
		if second(cloneIv, cloneBlock) == false {
			return byte(BS - i)
		}
	}
	panic("Err")
	return 0xFF
}

func forcePlaintextByte(prevBlock, plaintext []byte, first int, plainByte byte) {
	for i := first; i < BS; i++ {
		prevBlock[i] = prevBlock[i] ^ plaintext[i] ^ plainByte
	}
}

func findByte(prevBlock, targetBlock, plaintext []byte, pos int) {

	copyPrevBlock := append([]byte{}, prevBlock...)
	var padding byte
	if pos < BS-1 {
		padding = byte(BS - pos)
		forcePlaintextByte(copyPrevBlock, plaintext, pos+1, padding)
	}
	for c := 0; c <= 255; c++ {
		copyPrevBlock[pos] = byte(c)
		if second(copyPrevBlock, targetBlock) {
			if pos == BS-1 {
				padding = findPadding(copyPrevBlock, targetBlock)
			}
			plaintext[pos] = padding ^ byte(c) ^ prevBlock[pos]
		}
	}
}

func decryptSingleBlock(prevBlock, targetBlock []byte) []byte {
	plaintext := make([]byte, BS)
	for i := BS - 1; i >= 0; i-- {
		findByte(prevBlock, targetBlock, plaintext, i)
	}
	return plaintext
}

func oracleDecrypt(iv, encrypted []byte) []byte {
	result := decryptSingleBlock(iv, encrypted[0:BS])
	for block := 1; block < len(encrypted)/BS; block++ {
		prevBlock := encrypted[BS*(block-1) : BS*block]
		targetBlock := encrypted[BS*block : BS*(block+1)]
		result = append(result, decryptSingleBlock(prevBlock, targetBlock)...)
	}
	return result
}

func main() {
	s := inputStrings[rand.Intn(len(inputStrings))]
	original, _ := base64.StdEncoding.DecodeString(s)
	fmt.Println("Original: ", string(original))
	iv, encrypted := first(string(original))
	plaintext := oracleDecrypt(iv, encrypted)
	if tools.Pkcs7Validate(plaintext) != nil {
		panic("Invalid padding")
	}
	padding := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-padding]
	fmt.Println("Attacked: ", string(plaintext))
}
