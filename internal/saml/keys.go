// Package saml implements the identity-provider side of SAML 2.0 Web Browser
// SSO: parsing and validating AuthnRequests, and building signed Responses.
//
// Keyhaven only signs. It never verifies signatures from untrusted parties,
// which avoids the XML signature-wrapping class of SAML vulnerabilities.
// Trust in a service provider comes from registration: its entity ID and its
// exact Assertion Consumer Service URLs.
package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const keyBits = 3072

// GenerateKeyBundle creates an RSA-3072 key and a self-signed certificate
// valid for 10 years, as one PEM bundle. SAML service providers pin this
// certificate, so it must stay stable.
func GenerateKeyBundle(commonName string) (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Truncate(time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// ParseKeyBundle reads a PEM bundle holding an RSA private key and its certificate.
func ParseKeyBundle(bundle string) (*rsa.PrivateKey, *x509.Certificate, error) {
	var key *rsa.PrivateKey
	var cert *x509.Certificate
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("saml key: %w", err)
			}
			rk, ok := k.(*rsa.PrivateKey)
			if !ok {
				return nil, nil, errors.New("saml key: must be RSA")
			}
			key = rk
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("saml key: %w", err)
			}
			key = k
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("saml certificate: %w", err)
			}
			cert = c
		}
	}
	if key == nil || cert == nil {
		return nil, nil, errors.New("saml key bundle must contain a private key and a certificate")
	}
	if key.N.BitLen() < 2048 {
		return nil, nil, errors.New("saml key must be at least 2048 bits")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, errors.New("saml certificate does not match the private key")
	}
	return key, cert, nil
}

// Fingerprint is the certificate's SHA-256 fingerprint as AA:BB:… (what admins compare).
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}
