package main

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/robquant/cryptopals/pkg/tools"
)

func main() {
	inputBytes, _ := ioutil.ReadFile("input/input1_8.txt")
	lines := bytes.Split(inputBytes, []byte("\n"))
	for i, line := range lines {
		if repeatedBlocks := tools.CountSameBlocks(line, 16); repeatedBlocks > 0 {
			fmt.Printf("Line %d has %d repetitions\n", i+1, repeatedBlocks)
		}
	}
}
