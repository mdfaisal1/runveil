package infra

import "testing"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Setenv("RUNVEIL_SECRET_KEY", "test-passphrase")
	warnNoKeyOnce.Do(func() {}) // ensure no warning interferes

	const plain = "super-secret-oidc-client-secret"
	enc, err := EncryptSecret(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc == plain {
		t.Fatal("ciphertext should differ from plaintext when key is set")
	}
	if got := enc[:len(encPrefix)]; got != encPrefix {
		t.Fatalf("want %q prefix, got %q", encPrefix, got)
	}
	back, err := DecryptSecret(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if back != plain {
		t.Fatalf("round-trip mismatch: got %q", back)
	}
}

func TestDecryptLegacyPlaintextPassthrough(t *testing.T) {
	t.Setenv("RUNVEIL_SECRET_KEY", "test-passphrase")
	// An untagged (legacy) value is returned as-is.
	got, err := DecryptSecret("legacy-plaintext-secret")
	if err != nil {
		t.Fatalf("legacy decrypt: %v", err)
	}
	if got != "legacy-plaintext-secret" {
		t.Fatalf("legacy passthrough mismatch: got %q", got)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	t.Setenv("RUNVEIL_SECRET_KEY", "the-right-key")
	enc, err := EncryptSecret("payload")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Rotate the key — GCM auth must fail rather than return garbage.
	t.Setenv("RUNVEIL_SECRET_KEY", "a-different-key")
	if _, err := DecryptSecret(enc); err == nil {
		t.Fatal("expected decryption to fail with a rotated key")
	}
}

func TestEncryptNoKeyStoresPlaintext(t *testing.T) {
	t.Setenv("RUNVEIL_SECRET_KEY", "")
	enc, err := EncryptSecret("dev-secret")
	if err != nil {
		t.Fatalf("encrypt (no key): %v", err)
	}
	if enc != "dev-secret" {
		t.Fatalf("with no key, value should be stored as plaintext, got %q", enc)
	}
}
