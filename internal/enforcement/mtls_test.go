package enforcement

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genTestCerts writes a self-signed CA cert + server cert + client cert to a
// temporary directory and returns the directory path.
//
// Files created:
//
//	ca.crt     — CA certificate (PEM)
//	client.crt — client certificate signed by CA (PEM)
//	client.key — client private key (PEM)
func genTestCerts(t *testing.T) (caFile, certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()

	// Generate CA key.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	caFile = filepath.Join(dir, "ca.crt")
	if err := writePEMFile(caFile, "CERTIFICATE", caCertDER); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}

	// Generate client key + cert signed by CA.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen client key: %v", err)
	}
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	certFile = filepath.Join(dir, "client.crt")
	keyFile = filepath.Join(dir, "client.key")
	if err := writePEMFile(certFile, "CERTIFICATE", clientCertDER); err != nil {
		t.Fatalf("write client cert: %v", err)
	}
	if err := writePEMFile(keyFile, "EC PRIVATE KEY", clientKeyDER); err != nil {
		t.Fatalf("write client key: %v", err)
	}

	return caFile, certFile, keyFile
}

func writePEMFile(path, pemType string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	return pem.Encode(f, &pem.Block{Type: pemType, Bytes: der})
}

func TestWithMTLSConfig_Success(t *testing.T) {
	caFile, certFile, keyFile := genTestCerts(t)

	opt, err := WithMTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("WithMTLSConfig() error = %v", err)
	}
	if opt == nil {
		t.Fatal("WithMTLSConfig() returned nil option")
	}

	// Apply the option and verify the resulting TLS config.
	cfg := defaultGRPCConfig()
	opt(cfg)

	if cfg.insecure {
		t.Error("expected insecure=false after WithMTLSConfig")
	}
	if cfg.tlsConfig == nil {
		t.Fatal("expected non-nil tlsConfig after WithMTLSConfig")
	}
	if len(cfg.tlsConfig.Certificates) != 1 {
		t.Errorf("expected 1 client certificate, got %d", len(cfg.tlsConfig.Certificates))
	}
	if cfg.tlsConfig.RootCAs == nil {
		t.Error("expected non-nil RootCAs in TLS config")
	}
	if cfg.tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion=TLS13, got %d", cfg.tlsConfig.MinVersion)
	}
}

func TestWithMTLSConfig_MissingCertFile(t *testing.T) {
	_, err := WithMTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem", "/nonexistent/ca.pem")
	if err == nil {
		t.Fatal("WithMTLSConfig() expected error for missing files, got nil")
	}
}

func TestWithMTLSConfig_BadCAPEM(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "bad-ca.pem")
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	// Write a real cert/key pair but a bad CA.
	_, realCert, realKey := genTestCerts(t)

	// Copy real cert/key to our paths.
	realCertData, _ := os.ReadFile(realCert)
	realKeyData, _ := os.ReadFile(realKey)
	_ = os.WriteFile(certFile, realCertData, 0600)
	_ = os.WriteFile(keyFile, realKeyData, 0600)
	// Write invalid CA PEM.
	_ = os.WriteFile(caFile, []byte("not valid PEM data"), 0600)

	_, err := WithMTLSConfig(certFile, keyFile, caFile)
	if err == nil {
		t.Fatal("WithMTLSConfig() expected error for invalid CA PEM, got nil")
	}
}

func TestGRPCOptsFromEnv_Insecure(t *testing.T) {
	// No env vars set — should return insecure.
	t.Setenv("AC_ENFORCER_TLS_CERT", "")
	t.Setenv("AC_ENFORCER_TLS_KEY", "")
	t.Setenv("AC_ENFORCER_TLS_CA", "")

	opts, err := GRPCOptsFromEnv()
	if err != nil {
		t.Fatalf("GRPCOptsFromEnv() error = %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected 1 option, got %d", len(opts))
	}

	cfg := defaultGRPCConfig()
	opts[0](cfg)
	if !cfg.insecure {
		t.Error("expected insecure=true when no TLS env vars are set")
	}
}

func TestGRPCOptsFromEnv_MTLS(t *testing.T) {
	caFile, certFile, keyFile := genTestCerts(t)

	t.Setenv("AC_ENFORCER_TLS_CERT", certFile)
	t.Setenv("AC_ENFORCER_TLS_KEY", keyFile)
	t.Setenv("AC_ENFORCER_TLS_CA", caFile)

	opts, err := GRPCOptsFromEnv()
	if err != nil {
		t.Fatalf("GRPCOptsFromEnv() error = %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected 1 option, got %d", len(opts))
	}

	cfg := defaultGRPCConfig()
	opts[0](cfg)
	if cfg.insecure {
		t.Error("expected insecure=false for mTLS")
	}
	if cfg.tlsConfig == nil {
		t.Fatal("expected tlsConfig for mTLS")
	}
	if len(cfg.tlsConfig.Certificates) != 1 {
		t.Errorf("expected 1 client certificate, got %d", len(cfg.tlsConfig.Certificates))
	}
}

func TestGRPCOptsFromEnv_ServerOnlyTLS(t *testing.T) {
	caFile, _, _ := genTestCerts(t)

	t.Setenv("AC_ENFORCER_TLS_CERT", "")
	t.Setenv("AC_ENFORCER_TLS_KEY", "")
	t.Setenv("AC_ENFORCER_TLS_CA", caFile)

	opts, err := GRPCOptsFromEnv()
	if err != nil {
		t.Fatalf("GRPCOptsFromEnv() error = %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("expected 1 option, got %d", len(opts))
	}

	cfg := defaultGRPCConfig()
	opts[0](cfg)
	if cfg.insecure {
		t.Error("expected insecure=false for server-only TLS")
	}
	if cfg.tlsConfig == nil {
		t.Fatal("expected tlsConfig for server-only TLS")
	}
	// No client cert — server-only TLS.
	if len(cfg.tlsConfig.Certificates) != 0 {
		t.Errorf("expected 0 client certificates for server-only TLS, got %d", len(cfg.tlsConfig.Certificates))
	}
	if cfg.tlsConfig.RootCAs == nil {
		t.Error("expected RootCAs for server-only TLS")
	}
}

func TestGRPCOptsFromEnv_PartialCertMissingCA(t *testing.T) {
	// CERT+KEY set but no CA: only CA triggers TLS; CERT+KEY alone is meaningless
	// without CA. The function returns insecure in this case.
	_, certFile, keyFile := genTestCerts(t)

	t.Setenv("AC_ENFORCER_TLS_CERT", certFile)
	t.Setenv("AC_ENFORCER_TLS_KEY", keyFile)
	t.Setenv("AC_ENFORCER_TLS_CA", "")

	opts, err := GRPCOptsFromEnv()
	if err != nil {
		t.Fatalf("GRPCOptsFromEnv() error = %v", err)
	}

	cfg := defaultGRPCConfig()
	opts[0](cfg)
	// Without CA, we fall through to insecure.
	if !cfg.insecure {
		t.Error("expected insecure when CA not set (CERT+KEY without CA)")
	}
}
