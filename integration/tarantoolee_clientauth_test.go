// tarantoolee_clientauth_integration_test.go — mutual TLS (client certificate)
// interop with a locally installed Tarantool Enterprise Edition binary.
//
// TestTarantoolEE_Ping_ClientAuth launches a Tarantool EE instance with
// ssl_ca_file set (so Tarantool requires and verifies a client cert) and
// dials using OpenSSLDialer with SslCertFile + SslKeyFile. Two subtests cover
// RSA and ECDSA client key types; the server cert is the RSA pair in both
// subtests (the focus is on the client-auth flow, not the server key type).
//
// The test skips (not fails) when any of the following are absent:
//   - Tarantool EE binary
//   - testdata/tarantool/certs/{ca.crt,server.crt,server.key} (non-GOST)
//   - testdata/tarantool/certs/{client.crt,client.key} or
//     {client_ecdsa.crt,client_ecdsa.key} per subtest
//
// Generate certs with: bash testdata/tarantool/certs/gen.sh
//
// Run:
//
//	go test -run TestTarantoolEE_Ping_ClientAuth ./integration/ -v

package integration_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"

	tlsdialer "github.com/tarantool/go-tlsdialer/v2"
	"github.com/tarantool/go-tlsdialer/v2/backend/gostls"
)

// tarantoolClientAuthConfigTmpl is a Tarantool 3.x config that includes
// ssl_ca_file on the iproto listener, which causes Tarantool to request and
// verify a client certificate (mutual TLS).
var tarantoolClientAuthConfigTmpl = template.Must(template.New("client-auth-cfg").Parse(`
credentials:
  users:
    test:
      password: "test"
      roles: [super]

iproto:
  listen:
    - uri: "127.0.0.1:{{.Port}}"
      params:
        transport: ssl
        ssl_cert_file: "{{.CertFile}}"
        ssl_key_file: "{{.KeyFile}}"
        ssl_ca_file: "{{.CaFile}}"
        ssl_ciphers: "{{.Cipher}}"

process:
  work_dir: "{{.WorkDir}}"

snapshot:
  dir: "{{.WorkDir}}"

wal:
  dir: "{{.WorkDir}}"

groups:
  default:
    replicasets:
      default:
        instances:
          instance: {}
`))

// clientCertPaths returns the certDir and the absolute paths to the RSA and
// ECDSA client cert+key pairs.  ok is false if the common prerequisites
// (CA cert + RSA server pair) are missing — this is checked by certPaths, so
// we only check the client-specific files here at subtest time.
func clientCertDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "testdata", "tarantool", "certs"))
}

// TestTarantoolEE_Ping_ClientAuth drives a Tarantool EE instance configured
// for mutual TLS and dials with client certificates (RSA + ECDSA subtests).
func TestTarantoolEE_Ping_ClientAuth(t *testing.T) {
	skipUnlessTarantoolEE(t)

	certs, ok := certPaths(t)
	if !ok {
		t.Skip("testdata/tarantool/certs not populated; run testdata/tarantool/certs/gen.sh")
	}

	certDir := clientCertDir(t)

	subtests := []struct {
		name           string
		clientCertFile string
		clientKeyFile  string
	}{
		{
			name:           "RSA",
			clientCertFile: filepath.Join(certDir, "client.crt"),
			clientKeyFile:  filepath.Join(certDir, "client.key"),
		},
		{
			name:           "ECDSA",
			clientCertFile: filepath.Join(certDir, "client_ecdsa.crt"),
			clientKeyFile:  filepath.Join(certDir, "client_ecdsa.key"),
		},
	}

	// Cipher for both subtests: a widely-supported AEAD suite that works
	// with the RSA server cert used here.
	const cipher = "ECDHE-RSA-AES256-GCM-SHA384"

	for _, tc := range subtests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Per-subtest skip if client cert/key files are absent.
			if _, err := os.Stat(tc.clientCertFile); err != nil {
				t.Skipf("client cert for %s not found at %s: run testdata/tarantool/certs/gen.sh",
					tc.name, tc.clientCertFile)
			}
			if _, err := os.Stat(tc.clientKeyFile); err != nil {
				t.Skipf("client key for %s not found at %s: run testdata/tarantool/certs/gen.sh",
					tc.name, tc.clientKeyFile)
			}

			// Use a short /tmp/ttee-* workdir to stay under the macOS Unix
			// socket path limit (~104 bytes) that t.TempDir() busts.
			workDir, err := os.MkdirTemp("/tmp", "ttee-")
			require.NoError(t, err, "mkdtemp")
			t.Cleanup(func() { _ = os.RemoveAll(workDir) })

			port := reservePort(t)
			cfgPath := filepath.Join(workDir, "config.yml")

			cfg, err := os.Create(cfgPath)
			require.NoError(t, err, "create config")
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
				CertFile: certs.RSACert,
				KeyFile:  certs.RSAKey,
				CaFile:   certs.CaFile,
				WorkDir:  workDir,
			})
			_ = cfg.Close()
			require.NoError(t, err, "render config")

			cmd, cancel := startTarantool(t, cfgPath, workDir)
			t.Cleanup(func() {
				cancel()
				_ = cmd.Wait()
			})

			addr := fmt.Sprintf("127.0.0.1:%d", port)
			require.NoErrorf(t, waitForTCP(addr, 30*time.Second),
				"tarantool-ee did not open %s", addr)

			dialer := tlsdialer.OpenSSLDialer{
				// Cert CN in testdata is "localhost", so dial the hostname
				// (not the IP) to make SNI + cert verification line up.
				Address:     fmt.Sprintf("localhost:%d", port),
				User:        "test",
				Password:    "test",
				SslCaFile:   certs.CaFile,
				SslCertFile: tc.clientCertFile,
				SslKeyFile:  tc.clientKeyFile,
				SslCiphers:  cipher,
				Backend:     gostls.New(),
			}

			connectAndPing(t, dialer,
				fmt.Sprintf("%s client cert on %s (%s)", tc.name, addr, cipher))
		})
	}
}
