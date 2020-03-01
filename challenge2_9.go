package main

import (
	"fmt"

	"github.com/robquant/cryptopals/pkg/tools"
)

func main() {
	fmt.Printf("%v\n", tools.Pkcs7Pad([]byte("YELLOW SUBMARINE"), 20))
}
