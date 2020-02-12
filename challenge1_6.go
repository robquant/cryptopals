package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"

	"encoding/base64"

	"github.com/robquant/cryptopals/pkg/tools"
)

func main() {
	b1 := []byte("this is a test")
	b2 := []byte("wokka wokka!!!")
	fmt.Printf("Hamming distance: %d\n", tools.HammingDistance(b1, b2))
	input, _ := ioutil.ReadFile("input/input1_6.txt")
	lines := bytes.Split(input, []byte("\n"))
	joined := bytes.Join(lines, []byte(""))
	decoded, err := base64.StdEncoding.DecodeString(string(joined))
	if err != nil {
		log.Fatal("Decoding error ", err)
	}
	keyLength := tools.GuessKeyLength(decoded)
	transposed := tools.Transpose(decoded, keyLength)
	key := make([]byte, keyLength)
	for i := 0; i < keyLength; i++ {
		keyLetter, _ := tools.GuessKey(transposed[i])
		key[i] = keyLetter
	}
	fmt.Printf("Key: %s", string(key))
	fmt.Printf("%s", string(tools.RepeatedKeyXor(decoded, key)))
}
