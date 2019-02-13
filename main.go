package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"
)

func main() {

	// Generate RSA Keys
	wagnerPrivateKey, _ := generateKeyPair()
	wagnerPublicKey := &wagnerPrivateKey.PublicKey

	fmt.Println("Private Key : ", wagnerPrivateKey)
	fmt.Println("Public key ", wagnerPublicKey)

	//Encrypt Miryan Message
	message := []byte("Wagner AOS!")
	label := []byte("")
	hash := sha256.New()

	ciphertext, _ := encryptRSAMessage(hash, wagnerPrivateKey, message, label)

	fmt.Printf("OAEP encrypted [%s] to \n[%x]\n", string(message), ciphertext)
	fmt.Println()

	// Message - Signature
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := message
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	signature, _ := signPSS(wagnerPrivateKey, newhash, hashed, &opts)
	fmt.Printf("PSS Signature : %x\n", signature)

	// Decrypt Message
	plainText, _ := decryptRSAMessage(hash, wagnerPrivateKey, ciphertext, label)

	fmt.Printf("OAEP decrypted [%x] to \n[%s]\n", ciphertext, plainText)

	//Verify Signature
	verifyPSS(wagnerPublicKey, newhash, hashed, signature, &opts)

}

func generateKeyPair() (*rsa.PrivateKey, error) {

	keypair, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println(err)
		return keypair, nil
	}

	return keypair, nil
}

func encryptRSAMessage(hash hash.Hash, privateKey *rsa.PrivateKey, message []byte, label []byte) ([]byte, error) {

	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, &privateKey.PublicKey, message, label)

	if err != nil {
		fmt.Println(err)
		return ciphertext, nil
	}

	return ciphertext, nil
}

func signPSS(privateKey *rsa.PrivateKey, newhash crypto.Hash, hashed []byte, pssOptions *rsa.PSSOptions) ([]byte, error) {

	signature, err := rsa.SignPSS(rand.Reader, privateKey, newhash, hashed, pssOptions)

	if err != nil {
		fmt.Println(err)
		return signature, nil
	}

	return signature, nil
}

//Verify Signature
func verifyPSS(publicKey *rsa.PublicKey, newhash crypto.Hash, hashed []byte, signature []byte, pssOptions *rsa.PSSOptions) {

	//Verify Signature
	err := rsa.VerifyPSS(publicKey, newhash, hashed, signature, pssOptions)

	if err != nil {
		fmt.Println("Who are U? Verify Signature failed")
		print(err)
	} else {
		fmt.Println("Verify Signature successful")
	}

}

func decryptRSAMessage(hash hash.Hash, privateKey *rsa.PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {

	// Decrypt Message
	plainText, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, label)

	if err != nil {
		fmt.Println(err)
		return plainText, nil
	}

	return plainText, nil

}
