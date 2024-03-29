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
	bCryptPadPss       = 0x00000008 // bcrypt.h BCRYPT_PAD_PSS
)

var (
	nCrypt         = windows.MustLoadDLL("ncrypt.dll")
	nCryptSignHash = nCrypt.MustFindProc("NCryptSignHash")
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
		certContext, err = windows.CertFindCertificateInStore(
			store,
			windows.X509_ASN_ENCODING,
			0,
			windows.CERT_FIND_SUBJECT_STR,
			unsafe.Pointer(commonNamePtr),
			pPrevCertContext,
		)
		if err != nil {
			return nil, err
		}
		// We can extract the certificate chain and further filter the certificate we want here.
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
		pdwKeySpec                  uint32
		pfCallerFreeProvOrNCryptKey bool
	)
	err = windows.CryptAcquireCertificatePrivateKey(
		k.windowsCertContext,
		windows.CRYPT_ACQUIRE_CACHE_FLAG|windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
		nil,
		&privateKey,
		&pdwKeySpec,
		&pfCallerFreeProvOrNCryptKey,
	)
	if err != nil {
		return nil, err
	}

	// We always use RSA-PSS padding
	flags := nCryptSilentFlag | bCryptPadPss
	pPaddingInfo, err := getRsaPssPadding(opts)
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

func getRsaPssPadding(opts crypto.SignerOpts) (unsafe.Pointer, error) {
	pssOpts, ok := opts.(*rsa.PSSOptions)
	if !ok || pssOpts.Hash != crypto.SHA256 {
		return nil, fmt.Errorf("unsupported hash function %s", opts.HashFunc().String())
	}
	if pssOpts.SaltLength != rsa.PSSSaltLengthEqualsHash {
		return nil, fmt.Errorf("unsupported salt length %d", pssOpts.SaltLength)
	}
	sha256, _ := windows.UTF16PtrFromString("SHA256")
	// Create BCRYPT_PSS_PADDING_INFO structure:
	// typedef struct _BCRYPT_PSS_PADDING_INFO {
	// 	LPCWSTR pszAlgId;
	// 	ULONG   cbSalt;
	// } BCRYPT_PSS_PADDING_INFO;
	return unsafe.Pointer(
		&struct {
			pszAlgId *uint16
			cbSalt   uint32
		}{
			pszAlgId: sha256,
			cbSalt:   uint32(pssOpts.HashFunc().Size()),
		},
	), nil
}
