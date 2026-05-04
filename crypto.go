package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
)

func Encrypt(data []byte) ([]byte, error) {
	key := []byte(os.Getenv("NOT_MY_KEY"))

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	encryptedData := make([]byte, len(data))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encryptedData, data)

	combined := append(iv, encryptedData...)
	return combined, nil
}

func Decrypt(combined []byte) ([]byte, error) {
	key := []byte(os.Getenv("NOT_MY_KEY"))

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ivSize := block.BlockSize()
	iv := combined[:ivSize]
	encryptedData := combined[ivSize:]

	decryptedData := make([]byte, len(encryptedData))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decryptedData, encryptedData)

	return decryptedData, nil
}
