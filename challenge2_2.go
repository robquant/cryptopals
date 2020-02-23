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
	iv := make([]byte, 16)

	inputBytes, err := ioutil.ReadFile("input/input2_2.txt")
	if err != nil {
		log.Fatal(err)
	}
	input := strings.Replace(string(inputBytes), "\n", "", 0)
	ciphertext, _ := base64.StdEncoding.DecodeString(input)

	fmt.Println(string(tools.DecryptAesCBC(ciphertext, key, iv)))
}
