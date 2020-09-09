package tools

import (
	"testing"
)

func TestPkcs7Validate(t *testing.T) {
	paddingTests := []struct {
		padded []byte
		want   error
	}{
		{[]byte("ICE ICE BABY\x04\x04\x04\x04"), nil},
		{[]byte("ICE ICE BABY\x05\x05\x05\x05"), ErrPaddingInvalid},
		{[]byte("ICE ICE BABY\x01\x02\x03\x04"), ErrPaddingInvalid},
	}

	for _, tt := range paddingTests {
		got := Pkcs7Validate(tt.padded)
		if got != tt.want {
			t.Errorf("got %.2f want %.2f", got, tt.want)
		}
	}
}
