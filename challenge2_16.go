package main

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/robquant/cryptopals/pkg/tools"
)

var key, iv []byte
var prefix = []byte("comment1=cooking%20MCs;userdata=")
var postfix = []byte(";comment2=%20like%20a%20pound%20o%20bacon")

const bs = 16

func init() {
	rand.Seed(time.Now().UnixNano())
	key = make([]byte, 16)
	rand.Read(key)
	iv = make([]byte, 16)
	rand.Read(iv)
}

func first(in string) []byte {
	combined := make([]byte, 0)
	// prepend the string: "comment1=cooking%20MCs;userdata="
	combined = append(combined, prefix...)
	// quote out the ";" and "=" characters.
	quoted := strings.ReplaceAll(in, ";", "\";\"")
	quoted = strings.ReplaceAll(quoted, "=", "\"=\"")
	// input string, quoted out, in the middle
	combined = append(combined, []byte(quoted)...)
	// append the string: ";comment2=%20like%20a%20pound%20of%20bacon"
	combined = append(combined, postfix...)

	// encrypt it under the random AES key.
	return tools.EncryptAesCBC(combined, key, iv)
}

func second(ciphertext []byte) bool {
	// decrypt the string and look for the characters ";admin=true;"
	decryptedBytes, _ := tools.DecryptAesCBC(ciphertext, key, iv)
	decrypted := string(decryptedBytes)
	// return true or false based on whether the string exists.
	return strings.Contains(decrypted, ";admin=true;")
}

func findFirstChangedBlock(cipher1, cipher2 []byte) int {
	for i := 0; (i+1)*bs < len(cipher1); i++ {
		dist := tools.HammingDistance(cipher1[i*bs:(i+1)*bs], cipher2[i*bs:(i+1)*bs])
		if dist > 0 {
			return i
		}
	}
	return -1
}

func main() {
	ciphertext := first(strings.Repeat("A", 17))
	ciphertextFirstChanged := first("B" + strings.Repeat("A", 17))
	firstChangedBlock := findFirstChangedBlock(ciphertext, ciphertextFirstChanged)
	var ciphertextFlipped []byte
	var shift int
	for pos := 1; pos < 17; pos++ {
		ciphertextFlipped = first(strings.Repeat("A", pos) + "B" + strings.Repeat("A", 17-pos))
		if findFirstChangedBlock(ciphertext, ciphertextFlipped) > firstChangedBlock {
			shift = pos
			break
		}
	}
	padding := shift % bs
	// Offset of the first full block we have under control
	offset := bs*firstChangedBlock + padding
	injected := "_admin_true_"
	// Make sure our injected text starts at a block boundary
	ciphertext = first(strings.Repeat("A", 16+padding) + injected)
	target := []byte(";admin=true;")
	change, _ := tools.Xor(target, []byte(injected))
	for i := 0; i < len(change); i++ {
		ciphertext[offset+i] ^= change[i]
	}
	fmt.Println(second(ciphertext))
}
