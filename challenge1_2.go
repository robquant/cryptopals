package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/robquant/cryptopals/pkg/tools"
)

const (
	inputS    = "1c0111001f010100061a024b53535009181c"
	keyS      = "686974207468652062756c6c277320657965"
	expectedS = "746865206b696420646f6e277420706c6179"
)

func main() {

	input, _ := hex.DecodeString(inputS)
	key, _ := hex.DecodeString(keyS)
	xored, err := tools.Xor(input, key)
	if err != nil {
		log.Fatal(err)
	}
	if expectedS != hex.EncodeToString(xored) {
		fmt.Printf("Expected: %s\nGot     : %s\n", expectedS, hex.EncodeToString(xored))
		log.Fatal("Not equal!")
	} else {
		expected, _ := hex.DecodeString(expectedS)
		fmt.Println("Yeah!", string(expected))
	}
}
