package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/robquant/cryptopals/pkg/tools"
)

func main() {

	f, _ := os.Open("input/input1_4.txt")
	scanner := bufio.NewScanner(f)
	overallBestScore := 999.0
	var decryptedText string
	for scanner.Scan() {
		secretRaw, _ := hex.DecodeString(scanner.Text())
		secret := []byte(strings.ToLower(string(secretRaw)))
		bestKey, bestScore := tools.GuessKey(secret)
		decrypted := tools.XorSingleLetter(secret, bestKey)
		decryptedS := string(decrypted)
		if bestScore < overallBestScore {
			overallBestScore = bestScore
			decryptedText = decryptedS
		}
	}
	fmt.Printf("Score: %.3f -> Decrypted: %v\n", overallBestScore, decryptedText)

}
