package main

import (
	"encoding/base64"
	"fmt"

	"github.com/robquant/cryptopals/pkg/tools"
)

const (
	ciphertextBase64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
)

func main() {
	key := []byte("YELLOW SUBMARINE")
	nonce := uint64(0)
	ciphertext, _ := base64.StdEncoding.DecodeString(ciphertextBase64)
	fmt.Println(string(tools.EncryptAesCtr(ciphertext, key, nonce)))
}
