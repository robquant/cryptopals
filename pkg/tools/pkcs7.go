package tools

func Pkcs7Pad(in []byte, bs int) []byte {
	padBytes := bs - len(in)%bs
	out := make([]byte, len(in)+padBytes)
	copy(out, in)
	for i := 0; i < padBytes; i++ {
		out[len(in)+i] = byte(padBytes)
	}
	return out
}
