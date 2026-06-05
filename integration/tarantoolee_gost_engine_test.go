//go:build tarantoolee && openssl && openssl_gost_engine

// tarantoolee_gost_integration_test.go — GOST2012 cipher suite interop with a
// locally installed Tarantool Enterprise Edition binary plus the gost-engine
// OpenSSL provider.
//
// Build / run:
//
//	CGO_CFLAGS=-I/opt/homebrew/opt/openssl@3/include \
//	CGO_LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib \
//	go test -v -count=1 \
//	  -tags "tarantoolee openssl openssl_gost_engine" \
//	  -run TestTarantoolEE_Ping_GOST \
//	  ./
//
// The test skips (not fails) when any of the following are absent:
//   - Tarantool EE binary
//   - gost-engine .cnf and .dylib at their canonical Homebrew paths
//   - testdata/tarantool/certs/server_gost.{crt,key}
//
// gost-engine loading
//
// The gost engine is loaded into OpenSSL at Go package init time by
// backend_openssl_gost_engine.go (compiled under the same build tags). It
// resolves the engine via ENGINE_by_id, then GOST_ENGINE_LIB, then per-OS
// candidate paths, and exposes the result through GOSTEngineAvailable(). This
// test gates on that — it hardcodes no engine path, so it runs on any OS where
// gost-engine is installed (or GOST_ENGINE_LIB points at it).

package integration_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	tlsdialer "github.com/tarantool/go-tlsdialer"
	"github.com/tarantool/go-tlsdialer/backend/openssl"
)

// gostPingCiphers is the set of GOST cipher suites exercised by
// TestTarantoolEE_Ping_GOST.
//
// 0xFF85 (GOST2012-GOST8912-GOST8912) — gost-engine 3.0.3 registers this
// suite under the "LEGACY-" prefix in OpenSSL 3.x only; the plain name
// returns empty from `openssl ciphers`. Tarantool EE 3.x accepts the
// cipher by wire ID regardless of which name the client proposes.
//
// 0xC100 / 0xC101 (KUZNYECHIK / MAGMA, RFC 9367 GOST-2018) — gost-engine
// registers these under their plain names; no "LEGACY-" alias exists
// (confirmed via `openssl ciphers -V`).
//
// 0x0081 (GOST2001-GOST89-GOST89) — legacy CryptoPro suite; plain name,
// no "LEGACY-" alias. Uses a GOST R 34.10-2001 server cert (distinct
// paramset from the 2012 pair); routed via pickCertForCipher's
// HasPrefix("GOST2001-") branch.
var gostPingCiphers = []string{
	"LEGACY-GOST2012-GOST8912-GOST8912",
	"GOST2012-KUZNYECHIK-KUZNYECHIKOMAC",
	"GOST2012-MAGMA-MAGMAOMAC",
	"GOST2001-GOST89-GOST89",
}

// TestTarantoolEE_Ping_GOST launches a Tarantool EE instance configured with
// a GOST2012 server cert and exercises a Ping over each GOST cipher suite.
func TestTarantoolEE_Ping_GOST(t *testing.T) {
	if _, err := exec.LookPath(tarantoolEEBin()); err != nil {
		t.Skipf("tarantool-ee binary not on PATH (set TARANTOOL_EE_BIN to override): %v", err)
	}
	if !openssl.GOSTEngineAvailable() {
		t.Skipf("gost engine not loaded into OpenSSL: %v "+
			"(install gost-engine or set GOST_ENGINE_LIB)", openssl.GOSTEngineError())
	}

	certs, ok := certPaths(t)
	if !ok {
		t.Skip("testdata/tarantool/certs not populated; run testdata/tarantool/certs/gen.sh")
	}
	if _, err := os.Stat(certs.GOSTCert); err != nil {
		t.Skipf("GOST server cert not found at %s: "+
			"run testdata/tarantool/certs/gen.sh with gost-engine", certs.GOSTCert)
	}
	if _, err := os.Stat(certs.GOSTKey); err != nil {
		t.Skipf("GOST server key not found at %s: "+
			"run testdata/tarantool/certs/gen.sh with gost-engine", certs.GOSTKey)
	}

	for _, cipher := range gostPingCiphers {
		cipher := cipher
		t.Run(cipher, func(t *testing.T) {
			t.Parallel()

			// Use a short /tmp/ttee-* workdir to stay under the macOS Unix
			// socket path limit (~104 bytes) that t.TempDir() busts.
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
			certFile, keyFile := pickCertForCipher(certs, cipher)
			// Per-subtest cert existence: α/β share server_gost.* (already
			// checked at function level); γ needs server_gost2001.*, which
			// may be absent on checkouts that ran gen.sh against an older
			// gost-engine.cnf. Skip only the affected subtest.
			if _, err := os.Stat(certFile); err != nil {
				t.Skipf("server cert for %s not found at %s: "+
					"run testdata/tarantool/certs/gen.sh with gost-engine", cipher, certFile)
			}
			if _, err := os.Stat(keyFile); err != nil {
				t.Skipf("server key for %s not found at %s: "+
					"run testdata/tarantool/certs/gen.sh with gost-engine", cipher, keyFile)
			}
			err = tarantoolConfigTmpl.Execute(cfg, struct {
				Port     int
				Cipher   string
				CertFile string
				KeyFile  string
				WorkDir  string
			}{
				Port:     port,
				Cipher:   cipher,
				CertFile: certFile,
				KeyFile:  keyFile,
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
				Backend:    openssl.New(),
				Address:    fmt.Sprintf("localhost:%d", port),
				User:       "test",
				Password:   "test",
				SslCaFile:  certs.CaFile,
				SslCiphers: cipher,
			}

			connectAndPing(t, dialer, fmt.Sprintf("%s on %s", cipher, addr))
		})
	}
}
