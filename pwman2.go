/*

	This password manager uses AES (Advanced Encryption Standard) with a 128-bit key to encrypt and 
	decrypt the password. It also uses a random initialization vector to make it more secure. 
	The password is encrypted and decrypted using a cipher feedback (CFB) mode, which is a secure way to encrypt data in a stream.

	Note that this is just an example and should not be used in a production environment without further testing and security measures.

*/
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func main() {
	// Enter a password
	fmt.Print("Enter a password: ")
	var password string
	fmt.Scanln(&password)

	// Hash the password using SHA-256
	hashedPassword := sha256.Sum256([]byte(password))

	// Create a new AES cipher block
	block, err := aes.NewCipher(hashedPassword[:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Create a slice to hold the encrypted password
	encryptedPassword := make([]byte, len(password))

	// Encrypt the password using the cipher block and IV
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(encryptedPassword, []byte(password))

	// Encode the encrypted password and IV to base64
	base64EncryptedPassword := base64.StdEncoding.EncodeToString(append(iv, encryptedPassword...))

	// Print the encrypted password
	fmt.Println("Encrypted password: ", base64EncryptedPassword)

	// Decode the encrypted password and IV from base64
	decodedEncryptedPassword, err := base64.StdEncoding.DecodeString(base64EncryptedPassword)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Split the decoded data into the IV and encrypted password
	iv = decodedEncryptedPassword[:aes.BlockSize]
	decryptedPassword := decodedEncryptedPassword[aes.BlockSize:]

	// Decrypt the password using the cipher block and IV
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(decryptedPassword, decryptedPassword)

	// Print the decrypted password
	fmt.Println("Decrypted password: ", string(decryptedPassword))
}
