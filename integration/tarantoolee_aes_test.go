// tarantoolee_integration_test.go — end-to-end interop with a locally
// installed Tarantool Enterprise Edition binary.
//
// For each cipher suite from the Tarantool supported-ciphers list that the
// pure-Go backend can negotiate, the test:
//   1. Writes a minimal Tarantool 3.x config into t.TempDir() with a single
//      SSL iproto listener restricted to that one suite.
//   2. Launches `tarantool-ee` against that config and waits for the TCP
//      port to accept connections.
//   3. Dials via OpenSSLDialer + tarantool.Connect, executes a PingRequest,
//      and asserts the round-trip succeeds.
//   4. Kills the Tarantool process and lets the TempDir get cleaned up.
//
// Requirements:
//   - Tarantool Enterprise Edition 3.0+ as the `tarantool` on $PATH
//     (TARANTOOL_BIN overrides it, as in go-tarantool's test_helpers). The EE
//     binary carries the same name as CE; the edition is probed via
//     test_helpers.IsTarantoolEE. Community Edition has no iproto TLS.
//   - testdata/tarantool/certs populated via the openssl steps in
//     testdata/tarantool/README.md.
//
// There is no build tag: the test skips (not fails) when a requirement is
// missing, so it is safe to run against a bare checkout.
//
// Run:    go test -run TestTarantoolEE ./integration/
// Single: go test -run TestTarantoolEE_Ping/AES128-SHA ./integration/

package integration_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"
	tarantool "github.com/tarantool/go-tarantool/v3"
	"github.com/tarantool/go-tarantool/v3/test_helpers"

	tlsdialer "github.com/tarantool/go-tlsdialer"
	"github.com/tarantool/go-tlsdialer/backend/gostls"
)

// tarantoolEEBin is the binary name or absolute path of the Tarantool
// executable, resolved the same way go-tarantool's test_helpers does it, so
// the edition probed by skipUnlessTarantoolEE is the binary that gets
// launched. The EE binary is usually installed as plain `tarantool`.
func tarantoolEEBin() string {
	if v := os.Getenv("TARANTOOL_BIN"); v != "" {
		return v
	}
	return "tarantool"
}

// skipUnlessTarantoolEE skips unless the `tarantool` on PATH is Enterprise
// Edition 3.0 or newer. Community Edition has no iproto TLS, and the configs
// these tests render are Tarantool 3.x cluster configs (TT_CONFIG with
// groups/replicasets/instances), which 2.x cannot load.
func skipUnlessTarantoolEE(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath(tarantoolEEBin()); err != nil {
		t.Skipf("tarantool binary not found (set TARANTOOL_BIN to override): %v", err)
	}
	isEE, err := test_helpers.IsTarantoolEE()
	if err != nil {
		t.Skipf("cannot determine the Tarantool edition: %v", err)
	}
	if !isEE {
		t.Skip("Tarantool Enterprise Edition is required: CE has no iproto TLS")
	}
	old, err := test_helpers.IsTarantoolVersionLess(3, 0, 0)
	if err != nil {
		t.Skipf("cannot determine the Tarantool version: %v", err)
	}
	if old {
		t.Skip("Tarantool 3.0+ is required: the test renders a 3.x cluster config")
	}
}

// pingCiphers lists the suites this test exercises. These match the 24 AES
// suites the pure-Go backend currently supports (see tls/interop_test.go).
// ChaCha20-POLY1305 and GOST suites are intentionally omitted.
var pingCiphers = []string{
	"ECDHE-ECDSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES256-SHA384",
	"ECDHE-ECDSA-AES128-SHA256",
	"ECDHE-ECDSA-AES256-SHA",
	"ECDHE-ECDSA-AES128-SHA",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-SHA384",
	"ECDHE-RSA-AES128-SHA256",
	"ECDHE-RSA-AES256-SHA",
	"ECDHE-RSA-AES128-SHA",
	"DHE-RSA-AES256-GCM-SHA384",
	"DHE-RSA-AES128-GCM-SHA256",
	"DHE-RSA-AES256-SHA256",
	"DHE-RSA-AES128-SHA256",
	"DHE-RSA-AES256-SHA",
	"DHE-RSA-AES128-SHA",
	"AES256-GCM-SHA384",
	"AES128-GCM-SHA256",
	"AES256-SHA256",
	"AES128-SHA256",
	"AES256-SHA",
	"AES128-SHA",
}

// tarantoolConfigTmpl renders a self-contained Tarantool 3.x instance
// config: credentials, one SSL iproto listener, and instance-local work
// directories so parallel subtests do not collide on WAL/snap.
var tarantoolConfigTmpl = template.Must(template.New("cfg").Parse(`
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

// serverCerts holds the paths to the CA plus all server key-types.
//
// Tarantool's openssl build supports multiple server certificate kinds:
// an RSA cert used by RSA-kex, ECDHE-RSA, and DHE-RSA suites; an ECDSA
// cert used by ECDHE-ECDSA-* suites; and a GOST R 34.10-2012 cert used by
// GOST2012-* suites. We keep all pairs on disk and pick per cipher at
// subtest time. The GOST pair may be absent on checkouts without gost-engine;
// that only skips GOST subtests — non-GOST subtests are unaffected.
type serverCerts struct {
	CaFile       string
	RSACert      string
	RSAKey       string
	ECDSACert    string
	ECDSAKey     string
	GOSTCert     string
	GOSTKey      string
	GOST2001Cert string
	GOST2001Key  string
}

// certPaths locates the PEM files generated by testdata/tarantool/certs/gen.sh.
// Returns the paths and whether every file the harness needs is present.
func certPaths(t *testing.T) (serverCerts, bool) {
	t.Helper()

	_, thisFile, _, _ := runtime.Caller(0)
	certDir := filepath.Clean(
		filepath.Join(filepath.Dir(thisFile), "testdata", "tarantool", "certs"))

	c := serverCerts{
		CaFile:    filepath.Join(certDir, "ca.crt"),
		RSACert:   filepath.Join(certDir, "server.crt"),
		RSAKey:    filepath.Join(certDir, "server.key"),
		ECDSACert: filepath.Join(certDir, "server_ecdsa.crt"),
		ECDSAKey:  filepath.Join(certDir, "server_ecdsa.key"),
		// GOST pairs — populated unconditionally; callers check for file
		// existence before use. Missing GOST pair(s) must not block
		// RSA/ECDSA subtests.
		GOSTCert:     filepath.Join(certDir, "server_gost.crt"),
		GOSTKey:      filepath.Join(certDir, "server_gost.key"),
		GOST2001Cert: filepath.Join(certDir, "server_gost2001.crt"),
		GOST2001Key:  filepath.Join(certDir, "server_gost2001.key"),
	}
	// Only the CA + RSA + ECDSA set is required. Missing GOST files are
	// handled by the GOST subtest via its own Skip.
	for _, f := range []string{c.CaFile, c.RSACert, c.RSAKey, c.ECDSACert, c.ECDSAKey} {
		if _, err := os.Stat(f); err != nil {
			return serverCerts{}, false
		}
	}
	return c, true
}

// pickCertForCipher returns the cert+key pair appropriate for the cipher's
// key-exchange algorithm.
//   - GOST2001-* requires a GOST R 34.10-2001 server cert (checked first;
//     "GOST2001-" would otherwise be shadowed by the "GOST" 2012 branch).
//   - GOST2012-* and LEGACY-GOST2012-* (gost-engine 3.0.3 naming) require the
//     GOST R 34.10-2012 server cert.
//   - ECDHE-ECDSA-* requires an ECDSA server cert.
//   - Everything else uses the RSA cert.
func pickCertForCipher(c serverCerts, cipher string) (certFile, keyFile string) {
	if strings.HasPrefix(cipher, "GOST2001-") {
		return c.GOST2001Cert, c.GOST2001Key
	}
	if strings.HasPrefix(cipher, "GOST") || strings.HasPrefix(cipher, "LEGACY-GOST") {
		return c.GOSTCert, c.GOSTKey
	}
	if strings.HasPrefix(cipher, "ECDHE-ECDSA-") {
		return c.ECDSACert, c.ECDSAKey
	}
	return c.RSACert, c.RSAKey
}

// skipDHEUnderOpenSSL3 records why DHE-RSA-* suites are currently
// unvalidatable by this harness. Tarantool 3.x's iproto SSL listener exposes
// no ssl_dh_params config key, so the server uses OpenSSL's built-in DH
// parameters. Since OpenSSL 3.0 those are rejected by the default SECLEVEL=2
// (DH < 2048 bits); since OpenSSL 3.2 DHE is removed from the default cipher
// list entirely. Probing shows that appending :@SECLEVEL=0 to the server's
// ssl_ciphers (the only opt-out channel Tarantool accepts) still produces a
// "no shared cipher" handshake failure, so there is no in-harness path to
// revive these subtests without upstream changes to Tarantool.
const skipDHEUnderOpenSSL3 = "DHE-RSA suites cannot be validated: OpenSSL 3 SECLEVEL=2 " +
	"rejects Tarantool's built-in DH parameters and Tarantool 3.x has no config key " +
	"to supply 2048-bit params; :@SECLEVEL=0 in ssl_ciphers does not unblock it."

// reservedPorts remembers every port reservePort has handed out, so two
// parallel subtests cannot be given the same one.
var reservedPorts = struct {
	sync.Mutex
	seen map[int]bool
}{seen: map[int]bool{}}

// reservePort returns a TCP port that is free at the moment of the call by
// listening on :0 and closing immediately.
//
// Closing before Tarantool binds leaves a race with the rest of the machine,
// but the race that actually bit was inside this binary: with two dozen
// parallel subtests the kernel readily handed the just-released ephemeral port
// to the next caller, and the second instance died with "Address already in
// use" while its subtest dialled the first instance and got "no shared cipher".
// Ports are therefore handed out at most once per run.
func reservePort(t *testing.T) int {
	t.Helper()

	for attempt := 0; attempt < 100; attempt++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err, "reserve port")
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()

		reservedPorts.Lock()
		fresh := !reservedPorts.seen[port]
		reservedPorts.seen[port] = true
		reservedPorts.Unlock()

		if fresh {
			return port
		}
	}
	require.FailNow(t, "could not reserve an unused port in 100 attempts")
	return 0
}

// waitForTCP polls addr with short TCP dials until it succeeds or timeout.
func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %s (last err: %w)", timeout, lastErr)
}

// connectAndPing connects via the dialer and issues a Ping, retrying transient
// failures until timeout. waitForTCP only proves the port is open; under heavy
// parallel load Tarantool EE accepts the TCP connection before instance
// bootstrap finishes and the first auth attempt fails with "Instance bootstrap
// hasn't finished yet". Retrying absorbs that readiness race.
func connectAndPing(t *testing.T, dialer tarantool.Dialer, label string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := tarantool.Connect(ctx, dialer, tarantool.Opts{Timeout: 5 * time.Second})
		if err != nil {
			cancel()
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		_, err = conn.Do(tarantool.NewPingRequest()).Get()
		cancel()
		if err != nil {
			_ = conn.CloseGraceful()
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		t.Cleanup(func() { _ = conn.CloseGraceful() })
		t.Logf("ping OK: %s", label)
		return
	}
	require.FailNowf(t, "connect+ping did not succeed within timeout",
		"%s: %v", label, lastErr)
}

// OPENSSL_CONF is how an installed GOST engine gets activated for this
// process: go-openssl's shim calls OPENSSL_config(NULL) from its package
// init, before any of our code runs, so by the time this init executes
// OpenSSL is already configured and the variable has done its job.
//
// It must not reach a Tarantool child, though. Tarantool EE links its own
// OpenSSL with GOST built in, and a config that dlopen's an external
// gost-engine on top of it aborts the process inside ENGINE_register_ciphers.
// Dropping it here covers every child, including the instances started by
// go-tarantool's test_helpers, which pass the environment through untouched.
func init() {
	_ = os.Unsetenv("OPENSSL_CONF")
}

// startTarantool writes cfgPath, launches tarantool-ee against it, and
// returns the running *exec.Cmd. The caller must cancel the returned
// context to terminate the process.
func startTarantool(t *testing.T, cfgPath, workDir string) (*exec.Cmd, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, tarantoolEEBin(), "--name", "instance")
	cmd.Dir = workDir
	// Tarantool 3.x loads the cluster config from TT_CONFIG. Passing the
	// config path positionally instead makes tarantool try to execute it
	// as a Lua script after startup and crash on the YAML syntax.
	//
	// Strip OPENSSL_CONF from the subprocess environment. Tarantool EE uses
	// its own statically-compiled OpenSSL (with built-in GOST support) and
	// ignores the system openssl.cnf, but a host OPENSSL_CONF that loads an
	// external engine can cause NID conflicts and cert-decode failures when
	// gost-engine tries to load into a binary that already has GOST built in.
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "OPENSSL_CONF=") {
			env = append(env, kv)
		}
	}
	env = append(env, "TT_CONFIG="+cfgPath)
	cmd.Env = env
	// Surface tarantool logs in the test output for diagnosis.
	cmd.Stdout = testLogWriter{t: t, tag: "tarantool-stdout"}
	cmd.Stderr = testLogWriter{t: t, tag: "tarantool-stderr"}

	if err := cmd.Start(); err != nil {
		cancel()
		require.NoError(t, err, "start tarantool-ee")
	}
	return cmd, cancel
}

// testLogWriter forwards a child process's output into t.Log with a tag
// prefix so the test output stays readable under -v.
type testLogWriter struct {
	t   *testing.T
	tag string
}

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("[%s] %s", w.tag, p)
	return len(p), nil
}

// TestTarantoolEE_Ping drives a fresh tarantool-ee instance per cipher
// suite, connects with OpenSSLDialer, and asserts a successful Ping.
func TestTarantoolEE_Ping(t *testing.T) {
	skipUnlessTarantoolEE(t)

	certs, ok := certPaths(t)
	if !ok {
		t.Skip("testdata/tarantool/certs not populated; run testdata/tarantool/certs/gen.sh")
	}

	for _, cipher := range pingCiphers {
		cipher := cipher
		t.Run(cipher, func(t *testing.T) {
			t.Parallel()

			if strings.HasPrefix(cipher, "DHE-RSA-") {
				t.Skip(skipDHEUnderOpenSSL3)
			}

			// Tarantool's internal console socket lives under
			// <work_dir>/var/run/instance/tarantool.control. Unix sockaddr_un
			// on macOS caps paths at ~104 bytes, and t.TempDir() on darwin
			// returns a long /var/folders/... path that busts the limit. Use
			// a short /tmp/ttee-* directory instead and clean it up manually.
			workDir, err := os.MkdirTemp("/tmp", "ttee-")
			require.NoError(t, err, "mkdtemp")
			t.Cleanup(func() { _ = os.RemoveAll(workDir) })
			port := reservePort(t)
			cfgPath := filepath.Join(workDir, "config.yml")

			cfg, err := os.Create(cfgPath)
			require.NoError(t, err, "create config")
			certFile, keyFile := pickCertForCipher(certs, cipher)
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
			require.NoError(t, err, "render config")

			cmd, cancel := startTarantool(t, cfgPath, workDir)
			t.Cleanup(func() {
				cancel()
				// Wait so the goroutine piping stdout/stderr drains cleanly.
				_ = cmd.Wait()
			})

			addr := fmt.Sprintf("127.0.0.1:%d", port)
			require.NoErrorf(t, waitForTCP(addr, 30*time.Second),
				"tarantool-ee did not open %s", addr)

			dialer := tlsdialer.OpenSSLDialer{
				// Cert CN in testdata is "localhost", so dial the hostname
				// (not the IP) to make SNI + cert verification line up.
				Address:    fmt.Sprintf("localhost:%d", port),
				User:       "test",
				Password:   "test",
				SslCaFile:  certs.CaFile,
				SslCiphers: cipher,
				Backend:    gostls.New(),
			}

			connectAndPing(t, dialer, fmt.Sprintf("%s on %s", cipher, addr))
		})
	}
}
