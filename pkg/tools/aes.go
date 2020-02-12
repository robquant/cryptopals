package tools

import (
	"crypto/aes"
	"log"
)

func DecryptAesECB(ciphertext, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	bs := cipher.BlockSize()
	if len(ciphertext)%bs != 0 {
		panic("Need a multiple of the blocksize")
	}
	plaintext := make([]byte, 0)
	decryptedBlock := make([]byte, bs)
	for len(ciphertext) > 0 {
		cipher.Decrypt(decryptedBlock, ciphertext)
		plaintext = append(plaintext, decryptedBlock...)
		ciphertext = ciphertext[bs:]
	}
	padding := int(plaintext[len(plaintext)-1])

	return plaintext[:len(plaintext)-(padding+1)]
}
