package externalcas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

func TestDescribeKeyAndSPKI(t *testing.T) {
	ec256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsa3072, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		pub  crypto.PublicKey
		want string
	}{
		{&ec256.PublicKey, "ECDSA-P256"},
		{&ec384.PublicKey, "ECDSA-P384"},
		{&rsa3072.PublicKey, "RSA-3072"},
		{edPub, "Ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := describeKey(tt.pub); got != tt.want {
				t.Errorf("describeKey() = %q, want %q", got, tt.want)
			}
			der, err := x509.MarshalPKIXPublicKey(tt.pub)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(der)
			if got, want := spkiSHA256(tt.pub), hex.EncodeToString(sum[:]); got != want {
				t.Errorf("spkiSHA256() = %q, want %q", got, want)
			}
		})
	}

	if got := describeKey("not a key"); got != "string" {
		t.Errorf("describeKey(unknown) = %q, want %q", got, "string")
	}
	if got := spkiSHA256("not a key"); got != "unavailable" {
		t.Errorf("spkiSHA256(unknown) = %q, want %q", got, "unavailable")
	}
}
