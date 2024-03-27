//go:build darwin && cgo

package signer

/*
   #cgo LDFLAGS: -framework CoreFoundation -framework Security
   #include <CoreFoundation/CoreFoundation.h>
   #include <Security/Security.h>
*/
import "C"
import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"runtime"
	"time"
	"unsafe"
)

const (
	// TLS cipher suites: https://www.rfc-editor.org/rfc/rfc8446.html#section-9.1
	supportedAlgorithm = tls.PSSWithSHA256
	maxCertificatesNum = 10
)

func GetClientCertificate(commonName string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	getClientCert := func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
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

		// Find certificate using SecItemCopyMatching
		// https://developer.apple.com/documentation/security/1398306-secitemcopymatching
		identitySearch := C.CFDictionaryCreateMutable(
			C.kCFAllocatorDefault, maxCertificatesNum, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks,
		)
		defer C.CFRelease(C.CFTypeRef(unsafe.Pointer(identitySearch)))
		var commonNameCFString = stringToCFString(commonName)
		defer C.CFRelease(C.CFTypeRef(commonNameCFString))
		C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassIdentity))
		C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecAttrCanSign), unsafe.Pointer(C.kCFBooleanTrue))
		C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecMatchSubjectWholeString), unsafe.Pointer(commonNameCFString))
		// To filter by issuers, we must provide a CFDataRef array of DER-encoded ASN.1 items.
		// C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecMatchIssuers), unsafe.Pointer(issuerCFArray))
		C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecReturnRef), unsafe.Pointer(C.kCFBooleanTrue))
		C.CFDictionaryAddValue(identitySearch, unsafe.Pointer(C.kSecMatchLimit), unsafe.Pointer(C.kSecMatchLimitAll))
		var identityMatches C.CFTypeRef
		if status := C.SecItemCopyMatching(C.CFDictionaryRef(identitySearch), &identityMatches); status != C.errSecSuccess {
			return nil, fmt.Errorf("failed to find client certificate: %v", status)
		}
		defer C.CFRelease(identityMatches)

		var foundCert *x509.Certificate
		var foundIdentity C.SecIdentityRef
		identityMatchesArrayRef := C.CFArrayRef(identityMatches)
		numIdentities := int(C.CFArrayGetCount(identityMatchesArrayRef))
		fmt.Printf("Found %d identities\n", numIdentities)
		for i := 0; i < numIdentities; i++ {
			identityMatch := C.CFArrayGetValueAtIndex(identityMatchesArrayRef, C.CFIndex(i))
			x509Cert, err := identityRefToCert(C.SecIdentityRef(identityMatch))
			if err != nil {
				continue
			}
			// Make sure certificate is not expired
			if x509Cert.NotAfter.After(time.Now()) {
				foundCert = x509Cert
				foundIdentity = C.SecIdentityRef(identityMatch)
				fmt.Printf("Found certificate from issuer %s with public key type %T\n", x509Cert.Issuer.String(), x509Cert.PublicKey)
				break
			}
		}

		if foundCert == nil {
			return nil, fmt.Errorf("failed to find a valid client certificate")
		}

		// Grab the private key reference (does not contain the private key cleartext).
		var privateKey C.SecKeyRef
		if status := C.SecIdentityCopyPrivateKey(C.SecIdentityRef(foundIdentity), &privateKey); status != 0 {
			return nil, fmt.Errorf("failed to copy private key ref from identity: %v", status)
		}

		customSigner := &CustomSigner{
			x509Cert:   foundCert,
			privateKey: privateKey,
		}
		// Set a finalizer to release the private key reference when the CustomSigner is garbage collected.
		runtime.SetFinalizer(
			customSigner, func(c *CustomSigner) {
				C.CFRelease(C.CFTypeRef(c.privateKey))
			},
		)
		certificate := tls.Certificate{
			Certificate:                  [][]byte{foundCert.Raw},
			PrivateKey:                   customSigner,
			SupportedSignatureAlgorithms: []tls.SignatureScheme{supportedAlgorithm},
		}
		return &certificate, nil
	}
	return getClientCert
}

// identityRefToCert converts a C.SecIdentityRef into an *x509.Certificate
func identityRefToCert(identityRef C.SecIdentityRef) (*x509.Certificate, error) {
	// Convert the identity to a certificate
	var certificateRef C.SecCertificateRef
	if status := C.SecIdentityCopyCertificate(identityRef, &certificateRef); status != 0 {
		return nil, fmt.Errorf("failed to get certificate from identity: %v", status)
	}
	defer C.CFRelease(C.CFTypeRef(certificateRef))

	// Export the certificate to PEM
	// SecItemExport: https://developer.apple.com/documentation/security/1394828-secitemexport
	var pemDataRef C.CFDataRef
	if status := C.SecItemExport(
		C.CFTypeRef(certificateRef), C.kSecFormatPEMSequence, C.kSecItemPemArmour, nil, &pemDataRef,
	); status != 0 {
		return nil, fmt.Errorf("failed to export certificate to PEM: %v", status)
	}
	defer C.CFRelease(C.CFTypeRef(pemDataRef))
	certPEM := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(pemDataRef)), C.int(C.CFDataGetLength(pemDataRef)))

	var x509Cert *x509.Certificate
	for block, rest := pem.Decode(certPEM); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			var err error
			x509Cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing client certificate: %v", err)
			}
		}
	}
	return x509Cert, nil
}

// CustomSigner is a crypto.Signer that uses the client certificate and key to sign
type CustomSigner struct {
	x509Cert   *x509.Certificate
	privateKey C.SecKeyRef
}

func (k *CustomSigner) Public() crypto.PublicKey {
	fmt.Printf("crypto.Signer.Public\n")
	return k.x509Cert.PublicKey
}

func (k *CustomSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	fmt.Printf("crypto.Signer.Sign with key type %T, opts type %T, hash %s\n", k.Public(), opts, opts.HashFunc().String())

	// Convert the digest to a CFDataRef
	digestCFData := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&digest[0])), C.CFIndex(len(digest)))
	defer C.CFRelease(C.CFTypeRef(digestCFData))

	// SecKeyAlgorithm: https://developer.apple.com/documentation/security/seckeyalgorithm
	// SecKeyCreateSignature: https://developer.apple.com/documentation/security/1643916-seckeycreatesignature
	var cfErrorRef C.CFErrorRef
	signCFData := C.SecKeyCreateSignature(
		k.privateKey, C.kSecKeyAlgorithmRSASignatureDigestPSSSHA256, C.CFDataRef(digestCFData), &cfErrorRef,
	)
	if cfErrorRef != 0 {
		return nil, fmt.Errorf("failed to sign data: %v", cfErrorRef)
	}
	defer C.CFRelease(C.CFTypeRef(signCFData))

	// Convert CFDataRef to Go byte slice
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(signCFData)), C.int(C.CFDataGetLength(signCFData))), nil
}

// stringToCFString converts Go string to CFStringRef
func stringToCFString(s string) C.CFStringRef {
	bytes := []byte(s)
	ptr := (*C.UInt8)(&bytes[0])
	return C.CFStringCreateWithBytes(C.kCFAllocatorDefault, ptr, C.CFIndex(len(bytes)), C.kCFStringEncodingUTF8, C.false)
}
