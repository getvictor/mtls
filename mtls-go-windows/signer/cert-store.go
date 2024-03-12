//go:build windows

package signer

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"runtime"
	"unsafe"
)

const (
	// TLS cipher suites: https://www.rfc-editor.org/rfc/rfc8446.html#section-9.1
	supportedAlgorithm = tls.PSSWithSHA256
	commonName         = "testClientTLS"
	windowsStoreName   = "MY"
	nCryptSilentFlag   = 0x00000040 // ncrypt.h NCRYPT_SILENT_FLAG
	bcryptPadPSS       = 0x00000008 // bcrypt.h BCRYPT_PAD_PSS
)

var (
	crypt32                           = windows.MustLoadDLL("crypt32.dll")
	certFindCertificateInStore        = crypt32.MustFindProc("CertFindCertificateInStore")
	cryptAcquireCertificatePrivateKey = crypt32.MustFindProc("CryptAcquireCertificatePrivateKey")
	nCrypt                            = windows.MustLoadDLL("ncrypt.dll")
	nCryptSignHash                    = nCrypt.MustFindProc("NCryptSignHash")
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
		if certContextPtr == 0 {
			return nil, err
		}
		// We can extract the certificate chain and further filter the certificate we want here.
		certContext = (*windows.CertContext)(unsafe.Pointer(certContextPtr))
		break
	}

	customSigner := &CustomSigner{
		store:              store,
		windowsCertContext: certContext,
	}
	// Set a finalizer to release Windows resources when the CustomSigner is garbage collected.
	runtime.SetFinalizer(
		customSigner, func(c *CustomSigner) {
			_ = windows.CertFreeCertificateContext(c.windowsCertContext)
			_ = windows.CertCloseStore(c.store, 0)
		},
	)

	// Copy the certificate data so that we have our own copy outside the windows context
	encodedCert := unsafe.Slice(certContext.EncodedCert, certContext.Length)
	buf := bytes.Clone(encodedCert)
	foundCert, err := x509.ParseCertificate(buf)
	if err != nil {
		return nil, err
	}

	customSigner.x509Cert = foundCert

	// Make sure certificate is not expired
	//if foundCert.NotAfter.After(time.Now()) {
	//	return nil, fmt.Errorf("certificate with common name %s is expired", foundCert.Subject.CommonName)
	//}

	certificate := tls.Certificate{
		Certificate:                  [][]byte{foundCert.Raw},
		PrivateKey:                   customSigner,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{supportedAlgorithm},
	}
	fmt.Printf("Found certificate with common name %s\n", foundCert.Subject.CommonName)
	return &certificate, nil
}

// CustomSigner is a crypto.Signer that uses the client certificate and key to sign
type CustomSigner struct {
	store              windows.Handle
	windowsCertContext *windows.CertContext
	x509Cert           *x509.Certificate
}

func (k *CustomSigner) Public() crypto.PublicKey {
	fmt.Printf("crypto.Signer.Public\n")
	return k.x509Cert.PublicKey
}

func (k *CustomSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	fmt.Printf("crypto.Signer.Sign with key type %T, opts type %T, hash %s\n", k.Public(), opts, opts.HashFunc().String())

	// Get private key
	var (
		privateKey                  windows.Handle
		pdwKeySpec                  uintptr
		pfCallerFreeProvOrNCryptKey uintptr
	)
	resultBool, _, err := cryptAcquireCertificatePrivateKey.Call(
		uintptr(unsafe.Pointer(k.windowsCertContext)),
		windows.CRYPT_ACQUIRE_CACHE_FLAG|windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
		uintptr(0),
		uintptr(unsafe.Pointer(&privateKey)),
		pdwKeySpec,
		pfCallerFreeProvOrNCryptKey,
	)
	if resultBool == 0 {
		return nil, err
	}

	// RSA padding
	flags := nCryptSilentFlag | bcryptPadPSS
	pPaddingInfo, err := rsaPadding(opts)
	if err != nil {
		return nil, err
	}

	// Sign the digest
	// The first call to NCryptSignHash retrieves the size of the signature
	var size uint32
	success, _, _ := nCryptSignHash.Call(
		uintptr(privateKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if success != 0 {
		return nil, fmt.Errorf("NCryptSignHash: failed to get signature length: %#x", success)
	}

	// The second call to NCryptSignHash retrieves the signature
	signature = make([]byte, size)
	success, _, _ = nCryptSignHash.Call(
		uintptr(privateKey),
		uintptr(pPaddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if success != 0 {
		return nil, fmt.Errorf("NCryptSignHash: failed to generate signature: %#x", success)
	}
	return signature, nil
}

func rsaPadding(opts crypto.SignerOpts) (unsafe.Pointer, error) {
	pssOpts, ok := opts.(*rsa.PSSOptions)
	if !ok || pssOpts.Hash != crypto.SHA256 {
		return nil, fmt.Errorf("unsupported hash function %T", opts.HashFunc())
	}
	if pssOpts.SaltLength != rsa.PSSSaltLengthEqualsHash {
		return nil, fmt.Errorf("unsupported salt length %d", pssOpts.SaltLength)
	}
	sha256 := []uint16{'S', 'H', 'A', '2', '5', '6', 0}
	return unsafe.Pointer(
		&struct {
			algorithm  *uint16
			saltLength uint32
		}{
			algorithm:  &sha256[0],
			saltLength: uint32(pssOpts.HashFunc().Size()),
		},
	), nil
}
