package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/robquant/cryptopals/pkg/tools"
)

func main() {
	file, err := os.Open("input/input3_19.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	key := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)
	nonce := uint64(0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		plaintext, _ := base64.StdEncoding.DecodeString(scanner.Text())
		fmt.Println(tools.EncryptAesCtr(plaintext, key, nonce))
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
