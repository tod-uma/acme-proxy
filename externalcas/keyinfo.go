package externalcas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// describeKey returns a short description of a public key's type and size,
// e.g. "RSA-3072", "ECDSA-P256" or "Ed25519", for log messages.
func describeKey(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + strings.ReplaceAll(k.Curve.Params().Name, "-", "")
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", pub)
	}
}

// spkiSHA256 returns the hex SHA-256 of a public key's DER SubjectPublicKeyInfo,
// matching `openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER |
// sha256sum` on the issued certificate, so a logged request can be matched to
// the certificate a client ends up with.
func spkiSHA256(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "unavailable"
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
