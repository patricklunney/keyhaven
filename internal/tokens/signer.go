// Package tokens signs and verifies the JWTs Keyhaven issues.
package tokens

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	TypeAccessToken = "at+jwt" // RFC 9068
	TypeIDToken     = "JWT"
)

type Signer struct {
	key  *ecdsa.PrivateKey
	kid  string
	jwks jose.JSONWebKeySet
}

// GenerateKeyPEM creates a new P-256 private key in PKCS#8 PEM form.
func GenerateKeyPEM() (string, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// NewSigner parses a P-256 private key (PKCS#8 or SEC1 PEM).
func NewSigner(pemStr string) (*Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("signing key: no PEM block found")
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("signing key: must be an ECDSA key")
		}
		key = ek
	} else if ek, err2 := x509.ParseECPrivateKey(block.Bytes); err2 == nil {
		key = ek
	} else {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("signing key: must use curve P-256 (ES256)")
	}

	pub := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	pub.KeyID = base64.RawURLEncoding.EncodeToString(thumb)

	return &Signer{key: key, kid: pub.KeyID, jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}}}, nil
}

func (s *Signer) JWKS() jose.JSONWebKeySet { return s.jwks }

// Sign serializes claims as a compact JWS with the given "typ" header.
func (s *Signer) Sign(typ string, claims map[string]any) (string, error) {
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", s.kid)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: s.key}, opts)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jws, err := sig.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// Verify checks signature, "typ" header, issuer and expiry, returning the claims.
func (s *Signer) Verify(token, wantTyp, issuer string) (map[string]any, error) {
	return s.verify(token, wantTyp, issuer, true)
}

// VerifySignatureOnly is Verify without the expiry check (for id_token_hint).
func (s *Signer) VerifySignatureOnly(token, wantTyp, issuer string) (map[string]any, error) {
	return s.verify(token, wantTyp, issuer, false)
}

func (s *Signer) verify(token, wantTyp, issuer string, checkExp bool) (map[string]any, error) {
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("token: expected exactly one signature")
	}
	if typ, _ := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string); typ != wantTyp {
		return nil, fmt.Errorf("token: unexpected typ %q", typ)
	}
	payload, err := jws.Verify(&s.key.PublicKey)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	if iss, _ := claims["iss"].(string); iss != issuer {
		return nil, errors.New("token: wrong issuer")
	}
	if !checkExp {
		return claims, nil
	}
	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().Unix() >= int64(exp) {
		return nil, errors.New("token: expired")
	}
	return claims, nil
}

// HalfHash computes at_hash / c_hash for ES256: left half of SHA-256, base64url.
func HalfHash(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:16])
}
