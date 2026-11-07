package tokens

import (
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	pemStr, err := GenerateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(pemStr)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": "https://id.test", "sub": "u1", "exp": time.Now().Add(time.Minute).Unix()}
	at, _ := s.Sign(TypeAccessToken, claims)
	if _, err := s.Verify(at, TypeAccessToken, "https://id.test"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if _, err := s.Verify(at, TypeIDToken, "https://id.test"); err == nil {
		t.Fatal("access token accepted with wrong typ")
	}
	if _, err := s.Verify(at, TypeAccessToken, "https://other"); err == nil {
		t.Fatal("token accepted for wrong issuer")
	}
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	expired, _ := s.Sign(TypeAccessToken, claims)
	if _, err := s.Verify(expired, TypeAccessToken, "https://id.test"); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := s.VerifySignatureOnly(expired, TypeAccessToken, "https://id.test"); err != nil {
		t.Fatalf("signature-only verify failed: %v", err)
	}
	other, _ := GenerateKeyPEM()
	s2, _ := NewSigner(other)
	if _, err := s2.Verify(at, TypeAccessToken, "https://id.test"); err == nil {
		t.Fatal("token accepted under a different key")
	}
	if len(s.JWKS().Keys) != 1 || s.JWKS().Keys[0].KeyID == "" {
		t.Fatal("JWKS should publish one key with a kid")
	}
}
