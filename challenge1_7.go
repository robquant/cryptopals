package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/robquant/cryptopals/pkg/tools"
)

func main() {
	key := []byte("YELLOW SUBMARINE")

	inputBytes, err := ioutil.ReadFile("input/input1_7.txt")
	if err != nil {
		log.Fatal(err)
	}
	input := strings.Replace(string(inputBytes), "\n", "", 0)
	ciphertext, _ := base64.StdEncoding.DecodeString(input)
	plaintext := tools.DecryptAesECB(ciphertext, key)
	fmt.Printf("%s\n", string(plaintext))
}
