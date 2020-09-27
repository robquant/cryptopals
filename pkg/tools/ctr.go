package tools

type KeyStream interface {
	NextByte() byte
}

func ctrStream(input []byte, ks KeyStream) []byte {
	xored := make([]byte, len(input))
	for i, b := range input {
		xored[i] = b ^ ks.NextByte()
	}
	return xored
}
