//go:build tarantoolee && !openssl

// tarantoolee_gost_rsa_clientauth_integration_test.go — regression coverage
// for the mixed-algorithm mTLS path: GOST server cert + RSA client cert under
// a GOST cipher suite.
//
// Empirically (2026-04-22), Tarantool-EE 3.5.0 accepts an RSA client cert on
// its iproto listener regardless of the server cert's key algorithm. That is:
// server-side and client-side PKI are independent — EE's ssl_ca_file pins the
// client CA, and CertificateVerify uses whatever algorithm the client cert
// advertises (RSA/SHA-256 here), unrelated to the negotiated suite's KEX.
//
// This finding retires the most pressing reason to implement GOST-signed
// client-cert signing (see docs/tasks/client-cert-auth-gost.md): the existing
// RSA / ECDSA client-auth paths already cover the full EE mTLS integration
// matrix unless a specific deployment mandates a GOST client CA.
//
// Keeping the test green guards against the finding silently regressing.
//
// Build / run:
//
//	go test -v -count=1 \
//	  -tags "tarantoolee gost" \
//	  -run TestTarantoolEE_Ping_GOSTServer_RSAClientAuth \
//	  ./

package integration_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	tlsdialer "github.com/tarantool/go-tlsdialer"
	"github.com/tarantool/go-tlsdialer/backend/gostls"
)

func TestTarantoolEE_Ping_GOSTServer_RSAClientAuth(t *testing.T) {
	if _, err := exec.LookPath(tarantoolEEBin()); err != nil {
		t.Skipf("tarantool-ee binary not on PATH (set TARANTOOL_EE_BIN to override): %v", err)
	}

	certs, ok := certPaths(t)
	if !ok {
		t.Skip("testdata/tarantool/certs not populated; run testdata/tarantool/certs/gen.sh")
	}

	for _, f := range []string{certs.GOSTCert, certs.GOSTKey} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("GOST server pair not found at %s: "+
				"run testdata/tarantool/certs/gen.sh with gost-engine", f)
		}
	}

	certDir := clientCertDir(t)
	clientCertFile := filepath.Join(certDir, "client.crt")
	clientKeyFile := filepath.Join(certDir, "client.key")
	for _, f := range []string{clientCertFile, clientKeyFile} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("RSA client cert/key not found at %s: run testdata/tarantool/certs/gen.sh", f)
		}
	}

	workDir, err := os.MkdirTemp("/tmp", "ttee-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workDir) })

	port := reservePort(t)
	cfgPath := filepath.Join(workDir, "config.yml")

	cfg, err := os.Create(cfgPath)
	if err != nil {
		t.Fatalf("create config: %v", err)
	}

	const cipher = "GOST2012-GOST8912-GOST8912"
	err = tarantoolClientAuthConfigTmpl.Execute(cfg, struct {
		Port     int
		Cipher   string
		CertFile string
		KeyFile  string
		CaFile   string
		WorkDir  string
	}{
		Port:     port,
		Cipher:   cipher,
		CertFile: certs.GOSTCert,
		KeyFile:  certs.GOSTKey,
		CaFile:   certs.CaFile,
		WorkDir:  workDir,
	})
	_ = cfg.Close()
	if err != nil {
		t.Fatalf("render config: %v", err)
	}

	cmd, cancel := startTarantool(t, cfgPath, workDir)
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitForTCP(addr, 30*time.Second); err != nil {
		t.Fatalf("tarantool-ee did not open %s: %v", addr, err)
	}

	dialer := tlsdialer.OpenSSLDialer{
		Address:     fmt.Sprintf("localhost:%d", port),
		User:        "test",
		Password:    "test",
		SslCaFile:   certs.CaFile,
		SslCertFile: clientCertFile,
		SslKeyFile:  clientKeyFile,
		SslCiphers:  cipher,
		Backend:     gostls.New(),
	}

	connectAndPing(t, dialer, fmt.Sprintf(
		"GOST server cert + RSA client cert, cipher=%s, addr=%s", cipher, addr))
}
