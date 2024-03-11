//go:build windows

package signer

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"unsafe"
)

const (
	// TLS cipher suites: https://www.rfc-editor.org/rfc/rfc8446.html#section-9.1
	supportedAlgorithm = tls.PSSWithSHA256
	commonName         = "testClientTLS"
	windowsStoreName   = "MY"
)

var (
	crypt32                    = windows.MustLoadDLL("crypt32.dll")
	certFindCertificateInStore = crypt32.MustFindProc("CertFindCertificateInStore")
)

func GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	fmt.Printf("Server requested certificate\n")

	// Validate the supported signature schemes.
	signatureSchemeSupported := false
	for _, scheme := range info.SignatureSchemes {
		if scheme == supportedAlgorithm {
			signatureSchemeSupported = true
			break
		}
	}
	if !signatureSchemeSupported {
		return nil, fmt.Errorf("unsupported signature scheme")
	}

	// Open the certificate store
	storePtr, err := windows.UTF16PtrFromString(windowsStoreName)
	if err != nil {
		return nil, err
	}
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		uintptr(0),
		windows.CERT_SYSTEM_STORE_CURRENT_USER,
		uintptr(unsafe.Pointer(storePtr)),
	)
	if err != nil {
		return nil, err
	}

	// Find the certificate
	var pPrevCertContext *windows.CertContext
	var certContext *windows.CertContext
	commonNamePtr, err := windows.UTF16PtrFromString(commonName)
	for {
		certContextPtr, _, err := certFindCertificateInStore.Call(
			uintptr(store),
			uintptr(windows.X509_ASN_ENCODING),
			uintptr(0),
			uintptr(windows.CERT_FIND_SUBJECT_STR),
			uintptr(unsafe.Pointer(commonNamePtr)),
			uintptr(unsafe.Pointer(pPrevCertContext)),
		)
		if err != nil {
			return nil, err
		}
		// We can further filter the certificate we want here.
		certContext = (*windows.CertContext)(unsafe.Pointer(certContextPtr))
		break
	}
	defer func(ctx *windows.CertContext) {
		_ = windows.CertFreeCertificateContext(ctx)
	}(certContext)

	// Copy the certificate data so that we have our own copy outside the windows context
	encodedCert := unsafe.Slice(certContext.EncodedCert, certContext.Length)
	buf := bytes.Clone(encodedCert)
	foundCert, err := x509.ParseCertificate(buf)
	if err != nil {
		return nil, err
	}

	customSigner := &CustomSigner{
		x509Cert: foundCert,
	}
	certificate := tls.Certificate{
		Certificate:                  [][]byte{foundCert.Raw},
		PrivateKey:                   customSigner,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{supportedAlgorithm},
	}
	return &certificate, nil
}

// CustomSigner is a crypto.Signer that uses the client certificate and key to sign
type CustomSigner struct {
	x509Cert *x509.Certificate
}

func (k *CustomSigner) Public() crypto.PublicKey {
	fmt.Printf("crypto.Signer.Public\n")
	return k.x509Cert.PublicKey
}

func (k *CustomSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	fmt.Printf("crypto.Signer.Sign with key type %T, opts type %T, hash %s\n", k.Public(), opts, opts.HashFunc().String())
	return nil, errors.New("not implemented")
}
