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
	decrypted := string(tools.DecryptAesCBC(ciphertext, key, iv))
	// return true or false based on whether the string exists.
	return strings.Contains(decrypted, ";admin=true;")
}

func main() {
	ciphertext := first(strings.Repeat("A", 17))
	var ciphertextFlipped []byte
	for pos := 0; pos < 17; pos++ {
		ciphertextFlipped = first(strings.Repeat("A", pos) + "B" + strings.Repeat("A", 17-pos))
		// Magic with the ciphertext
		for i := 0; (i+1)*bs < len(ciphertext); i++ {
			dist := tools.HammingDistance(ciphertext[i*bs:(i+1)*bs], ciphertextFlipped[i*bs:(i+1)*bs])
			fmt.Printf("Shift: %d, Block: %d, Dist: %d\n", pos, i, dist)
		}
		fmt.Println()
	}
}
