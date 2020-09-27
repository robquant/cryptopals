package tools

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
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

	return plaintext[:len(plaintext)-padding]
}

func EncryptAesECB(plaintext, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	bs := cipher.BlockSize()
	plaintext = Pkcs7Pad(plaintext, bs)
	ciphertext := make([]byte, 0)
	encryptedBlock := make([]byte, bs)
	for len(plaintext) > 0 {
		cipher.Encrypt(encryptedBlock, plaintext)
		ciphertext = append(ciphertext, encryptedBlock...)
		plaintext = plaintext[bs:]
	}
	return ciphertext
}

func EncryptAesCBC(plaintext, key, iv []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	bs := cipher.BlockSize()
	plaintext = Pkcs7Pad(plaintext, bs)
	ciphertext := make([]byte, 0)
	encryptedBlock := make([]byte, bs)
	// Initialization vector for first round
	copy(encryptedBlock, iv)
	var nextBlock []byte
	for len(plaintext) > 0 {
		nextBlock, _ = Xor(encryptedBlock, plaintext[:bs])
		cipher.Encrypt(encryptedBlock, nextBlock)
		ciphertext = append(ciphertext, encryptedBlock...)
		plaintext = plaintext[bs:]
	}
	return ciphertext
}

func DecryptAesCBC(ciphertext, key, iv []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	bs := cipher.BlockSize()
	if len(ciphertext)%bs != 0 {
		panic("Need a multiple of the blocksize")
	}
	previousBlock := append([]byte{}, iv...)
	plaintext := make([]byte, 0)
	decryptedBlock := make([]byte, bs)
	for len(ciphertext) > 0 {
		cipher.Decrypt(decryptedBlock, ciphertext[:bs])
		decryptedBlock, _ = Xor(decryptedBlock, previousBlock)
		copy(previousBlock, ciphertext[:bs])
		plaintext = append(plaintext, decryptedBlock...)
		ciphertext = ciphertext[bs:]
	}

	err = Pkcs7Validate(plaintext)
	if err != nil {
		return nil, err
	}
	padding := int(plaintext[len(plaintext)-1])

	return plaintext[:len(plaintext)-padding], nil
}

type AesCtrKeyStream struct {
	cipher          cipher.Block
	nonce           uint64
	byteCounter     int
	currentKeyBlock []byte
	readIndex       int
}

func NewAesCtrKeyStream(key []byte, nonce uint64) *AesCtrKeyStream {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	return &AesCtrKeyStream{
		cipher:          cipher,
		nonce:           nonce,
		byteCounter:     0,
		currentKeyBlock: make([]byte, 16),
		readIndex:       0,
	}
}

func (ks *AesCtrKeyStream) NextByte() byte {
	if ks.readIndex%ks.cipher.BlockSize() == 0 {
		counter := uint64(ks.byteCounter / ks.cipher.BlockSize())
		block := make([]byte, 16)
		binary.LittleEndian.PutUint64(block, ks.nonce)
		binary.LittleEndian.PutUint64(block[8:], counter)
		ks.cipher.Encrypt(ks.currentKeyBlock, block)
		ks.readIndex = 0
	}
	b := ks.currentKeyBlock[ks.readIndex]
	ks.readIndex++
	ks.byteCounter++
	return b
}

func EncryptAesCtr(plaintext, key []byte, nonce uint64) []byte {
	ks := NewAesCtrKeyStream(key, nonce)
	return ctrStream(plaintext, ks)
}

func DecryptAesCtr(ciphertext, key []byte, nonce uint64) []byte {
	ks := NewAesCtrKeyStream(key, nonce)
	return ctrStream(ciphertext, ks)
}
