package signer

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

func GetClientCertificate(clientCertPath string, clientKeyPath string) (*tls.Certificate, error) {
	fmt.Printf("Server requested certificate\n")
	if clientCertPath == "" || clientKeyPath == "" {
		return nil, errors.New("client certificate and key are required")
	}
	clientBytes, err := os.ReadFile(clientCertPath)
	if err != nil {
		return nil, fmt.Errorf("error reading client certificate: %w", err)
	}
	var cert *x509.Certificate
	for block, rest := pem.Decode(clientBytes); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing client certificate: %v", err)
			}
		}
	}

	certificate := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey: &CustomSigner{
			x509Cert:       cert,
			clientCertPath: clientCertPath,
			clientKeyPath:  clientKeyPath,
		},
	}
	return &certificate, nil
}

// CustomSigner is a crypto.Signer that uses the client certificate and key to sign
type CustomSigner struct {
	x509Cert       *x509.Certificate
	clientCertPath string
	clientKeyPath  string
}

func (k *CustomSigner) Public() crypto.PublicKey {
	fmt.Printf("crypto.Signer.Public\n")
	return k.x509Cert.PublicKey
}
func (k *CustomSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (
	signature []byte, err error,
) {
	fmt.Printf("crypto.Signer.Sign\n")
	tlsCert, err := tls.LoadX509KeyPair(k.clientCertPath, k.clientKeyPath)
	if err != nil {
		log.Fatalf("error loading client certificate: %v", err)
	}
	fmt.Printf("Sign using %T\n", tlsCert.PrivateKey)
	return tlsCert.PrivateKey.(crypto.Signer).Sign(rand, digest, opts)
}
