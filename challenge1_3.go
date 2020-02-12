package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/robquant/cryptopals/pkg/tools"
)

const (
	secretS = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
)

func main() {

	secretRaw, _ := hex.DecodeString(secretS)
	secret := []byte(strings.ToLower(string(secretRaw)))
	bestKey, _ := tools.GuessKey(secret)
	decrypted := tools.XorSingleLetter(secret, bestKey)
	decryptedS := strings.ToLower(string(decrypted))
	fmt.Printf("Key: %c -> Decrypted: %v\n", rune(bestKey), decryptedS)

}
