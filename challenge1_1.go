package main

import (
	"encoding/hex"
	"fmt"
	"log"
)

//import "encoding/hex"

const (
	input        = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected     = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	inputWiki    = "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure."
	expectedWiki = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4="
	encodeStd    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

func base64(c byte) byte {
	return encodeStd[c]
}

func encode(input []byte) []byte {
	decoded := input
	// Pad with 0 bytes
	for len(decoded)%3 != 0 {
		decoded = append(decoded, 0)
	}

	var result []byte
	for i := 0; i < len(decoded)/3; i++ {
		current := uint32(decoded[3*i]) << 16
		current |= uint32(decoded[3*i+1]) << 8
		current |= uint32(decoded[3*i+2])
		for b := 3; b >= 0; b-- {
			shiftBy := 6 * b
			mask := uint32(63) << shiftBy
			r := byte((current & mask) >> shiftBy)
			result = append(result, base64(r))
		}
	}
	fillBytes := len(decoded) - len(input)
	for i := 0; i < fillBytes; i++ {
		result[len(result)-1-i] = '='
	}
	return result
}

func main() {
	decoded, _ := hex.DecodeString(input)
	result := encode(decoded)
	resultWikipedia := encode([]byte(inputWiki))
	if string(resultWikipedia) != expectedWiki {
		log.Fatal("Not equal wikipedia!")
	} else {
		fmt.Println("Yeah!")
	}
	if string(result) != expected {
		log.Fatal("Not equal!")
	} else {
		fmt.Println("Yeah!", string(decoded))
	}
}
