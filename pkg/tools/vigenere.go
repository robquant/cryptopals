package tools

import (
	"fmt"
	"math/bits"
)

var english = map[byte]float64{
	' ': 0.192,
	'e': 0.125,
	't': 0.093,
	'a': 0.0804,
	'o': 0.0764,
	'i': 0.0757,
	'n': 0.0723,
	's': 0.0651,
	'r': 0.0628,
	'h': 0.05,
	'l': 0.04,
	'd': 0.038,
	'c': 0.0334,
}

func HammingDistance(b1, b2 []byte) int {
	total := 0
	for i := 0; i < len(b1); i++ {
		total += bits.OnesCount8(b1[i] ^ b2[i])
	}
	return total
}

func GuessKeyLength(encrypted []byte) int {
	maxKeyLength := 40
	var bestKeyLength int
	lowestHammingDist := 999.0
	for keyLength := 1; keyLength < maxKeyLength; keyLength++ {
		total := 0
		nblocks := 8
		for block := 0; block < nblocks; block++ {
			b1 := encrypted[2*block*keyLength : (2*block+1)*keyLength]
			b2 := encrypted[(2*block+1)*keyLength : 2*(block+1)*keyLength]
			total += HammingDistance(b1, b2)
		}
		normalizedDist := float64(total) / float64(nblocks*keyLength)
		fmt.Printf("%d : %f\n", keyLength, normalizedDist)
		if normalizedDist < lowestHammingDist {
			lowestHammingDist = normalizedDist
			bestKeyLength = keyLength
		}
	}
	return bestKeyLength
}

func Transpose(input []byte, keyLength int) [][]byte {
	result := make([][]byte, keyLength)
	for i := 0; i < keyLength; i++ {
		result[i] = make([]byte, 0)
	}
	for i, b := range input {
		result[i%keyLength] = append(result[i%keyLength], b)
	}
	return result
}

func countLetters(s []byte) map[byte]int {
	counts := make(map[byte]int)
	for _, r := range s {
		counts[r]++
	}
	return counts
}

func frequencies(counts map[byte]int) map[byte]float64 {
	total := 0
	for _, value := range counts {
		total += value
	}
	res := make(map[byte]float64)
	for key, value := range counts {
		res[key] = float64(value) / float64(total)
	}
	return res
}

func score(frequencies map[byte]float64) float64 {
	score := 0.0
	for letter, freq := range english {
		diff := freq - frequencies[letter]
		score += diff * diff
	}
	return score
}

func GuessKey(secret []byte) (byte, float64) {
	var bestKey byte
	var bestScore = 999.0
	var key int
	for key = 0; key <= 255; key++ {
		decrypted := XorSingleLetter(secret, byte(key))
		counts := countLetters(decrypted)
		scoreForKey := score(frequencies(counts))
		if scoreForKey < bestScore {
			bestKey = byte(key)
			bestScore = scoreForKey
		}
	}
	return bestKey, bestScore
}
