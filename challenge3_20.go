package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/robquant/cryptopals/pkg/tools"
)

func main() {
	file, err := os.Open("input/input3_19.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	minTextLength := 999
	ciphertexts := make([][]byte, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ciphertext, _ := base64.StdEncoding.DecodeString(scanner.Text())
		if len(ciphertext) < minTextLength {
			minTextLength = len(ciphertext)
		}
		ciphertexts = append(ciphertexts, ciphertext)
	}
	for i := range ciphertexts {
		ciphertexts[i] = ciphertexts[i][:minTextLength]
	}
	transposed := make([][]byte, minTextLength)
	for i := 0; i < minTextLength; i++ {
		transposed[i] = make([]byte, len(ciphertexts))
	}
	for _, text := range ciphertexts {
		for i, c := range text {
			transposed[i] = append(transposed[i], c)
		}
	}
	key := make([]byte, minTextLength)
	for i := 0; i < minTextLength; i++ {
		key[i], _ = tools.GuessKey(transposed[i])
	}
	for _, ciphertext := range ciphertexts {
		plaintext, _ := tools.Xor(ciphertext, key)
		fmt.Println(string(plaintext))
	}
}
