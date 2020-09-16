package tools

import "errors"

var ErrPaddingInvalid = errors.New("Pkcs7Padding not valid")

func Pkcs7Pad(in []byte, bs int) []byte {
	padBytes := bs - len(in)%bs
	out := make([]byte, len(in)+padBytes)
	copy(out, in)
	for i := 0; i < padBytes; i++ {
		out[len(in)+i] = byte(padBytes)
	}
	return out
}

func Pkcs7Validate(in []byte) error {
	padBytes := in[len(in)-1]
	if int(padBytes) > len(in) {
		return ErrPaddingInvalid
	}
	for _, b := range in[len(in)-int(padBytes):] {
		if b != padBytes {
			return ErrPaddingInvalid
		}
	}
	return nil
}
