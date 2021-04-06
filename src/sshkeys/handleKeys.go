package sshkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"path"
	"time"
)

// look for RSA keys in the given path. If the files doesn't exist create them on demand
func HandleRSAKeys(rsaPrivPath string, rsaPubPath string, createIfNotExisting bool) {
	if (!existsFileOrDir(rsaPrivPath) || !existsFileOrDir(rsaPubPath)) && createIfNotExisting {
		if dirname := path.Dir(rsaPrivPath); !existsFileOrDir(dirname) {
			if err := os.MkdirAll(dirname, 0700); err != nil {
				log.Fatal(err.Error())
			}
		}

		if dirname := path.Dir(rsaPubPath); !existsFileOrDir(dirname) {
			if err := os.MkdirAll(dirname, 0700); err != nil {
				log.Fatal(err.Error())
			}
		}
		start := time.Now()
		bitSize := 4096

		privateKey, err := generatePrivateKey(bitSize)
		if err != nil {
			log.Fatal(err.Error())
		}

		publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
		if err != nil {
			log.Fatal(err.Error())
		}

		privateKeyBytes := encodePrivateKeyToPEM(privateKey)

		log.Printf("generate Keys in %s\n", time.Since(start))
		if err := ioutil.WriteFile(rsaPrivPath, privateKeyBytes, 0600); err != nil {
			log.Fatal(err.Error())
		}

		log.Printf("private key saved to: %s", rsaPrivPath)

		if err := ioutil.WriteFile(rsaPubPath, publicKeyBytes, 0600); err != nil {
			log.Fatal(err.Error())
		}
		log.Printf("public key saved to: %s", rsaPubPath)
	}
}

func existsFileOrDir(name string) bool {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		return false
	}
	return true
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privateKey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privateKey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)
	return pubKeyBytes, nil
}
