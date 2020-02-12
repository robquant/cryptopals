package tools

func CountSameBlocks(line []byte, bs int) int {
	d := make(map[string]int)
	for i := 0; i < len(line); i += bs {
		d[string(line[i:i+bs])]++
	}
	total := 0
	for _, val := range d {
		total += val - 1
	}
	return total
}
