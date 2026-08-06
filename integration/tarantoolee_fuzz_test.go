//go:build !openssl

// FuzzRequestBatch fuzzes the full live path — dialer + connection — over every
// cipher suite the pure-Go gostls backend can negotiate. One Tarantool EE
// instance is launched with one SSL iproto listener per server-cert type (RSA,
// ECDSA, GOST 2012, GOST 2001), a gostls connection is opened per suite, and
// each fuzz input picks a suite and runs a decoded batch of varied iproto
// requests over it. It skips when the EE binary or certs are absent.
//
//	export TARANTOOL_BIN=/path/to/tarantool-ee   # or put EE on PATH
//	CGO_ENABLED=0 go test -run FuzzRequestBatch \
//	    -fuzz FuzzRequestBatch -fuzztime 60s ./integration/

package integration_test

import (
	"bytes"
	"context"
	"errors"
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

	tlsdialer "github.com/tarantool/go-tlsdialer"
	"github.com/tarantool/go-tlsdialer/backend/gostls"
)

const (
	fuzzSpaceName = "fuzz_space"
	// fuzzKeyMod bounds primary keys so the space cannot grow unbounded.
	fuzzKeyMod = 4096
	// fuzzCanaryKey/Val: the integrity probe. The key sits outside the fuzz key
	// range; the value is constant so the canary holds under concurrent runs.
	fuzzCanaryKey = uint64(1_000_000)
	fuzzCanaryVal = "canary"
	fuzzMaxOps    = 64
	fuzzMaxField  = 4096
)

// fuzzConfigTmpl renders an instance with one SSL listener per cert type.
var fuzzConfigTmpl = template.Must(template.New("fuzzcfg").Parse(`
credentials:
  users:
    test:
      password: "test"
      roles: [super]

iproto:
  listen:
{{- range .Listeners}}
    - uri: "127.0.0.1:{{.Port}}"
      params:
        transport: ssl
        ssl_cert_file: "{{.CertFile}}"
        ssl_key_file: "{{.KeyFile}}"
        ssl_ciphers: "{{.Ciphers}}"
{{- end}}

process:
  work_dir: "{{.WorkDir}}"

# Small footprint: the fuzzing engine runs one instance per worker process, so
# default memtx sizing would thrash under load.
memtx:
  memory: 67108864

snapshot:
  dir: "{{.WorkDir}}"

wal:
  dir: "{{.WorkDir}}"
  mode: none

groups:
  default:
    replicasets:
      default:
        instances:
          instance: {}
`))

// ---- shared instance ---------------------------------------------------------

type fuzzListener struct {
	Port     int
	CertFile string
	KeyFile  string
	Ciphers  string
}

type fuzzEndpoint struct {
	cipher string
	conn   *tarantool.Connection
}

type fuzzEnv struct {
	cancel  context.CancelFunc
	cmd     *exec.Cmd
	workDir string
	conns   []*tarantool.Connection
	pool    []fuzzEndpoint
}

var (
	fuzzOnce   sync.Once
	fuzzShared *fuzzEnv
	fuzzSkip   string
)

// fuzzEnvSetup returns the per-cipher connection pool, launching the instance
// once. It skips the caller when the EE binary or certs are missing.
func fuzzEnvSetup(tb testing.TB) []fuzzEndpoint {
	tb.Helper()
	fuzzOnce.Do(func() { fuzzShared, fuzzSkip = startFuzzEnv() })
	if fuzzSkip != "" {
		tb.Skip(fuzzSkip)
	}
	return fuzzShared.pool
}

// fuzzCiphers lists the suites gostls can negotiate against EE: the AES suites
// minus DHE-RSA (no ssl_dh_params on Tarantool 3.x; see skipDHEUnderOpenSSL3)
// plus the pure-Go GOST suites.
func fuzzCiphers() []string {
	out := make([]string, 0, len(pingCiphers)+len(gostPingCiphersPure))
	for _, c := range pingCiphers {
		if strings.HasPrefix(c, "DHE-RSA-") {
			continue
		}
		out = append(out, c)
	}
	return append(out, gostPingCiphersPure...)
}

// startFuzzEnv launches one EE instance with a listener per cert type, opens a
// gostls connection per cipher, and provisions the scratch space. A missing
// prerequisite yields a non-empty skip reason rather than a failure.
func startFuzzEnv() (*fuzzEnv, string) {
	bin := tarantoolEEBin()
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Sprintf(
			"tarantool-ee binary not on PATH (set TARANTOOL_EE_BIN to override): %v", err)
	}

	certDir := fuzzCertDir()
	caFile := filepath.Join(certDir, "ca.crt")
	certs := serverCerts{
		CaFile:       caFile,
		RSACert:      filepath.Join(certDir, "server.crt"),
		RSAKey:       filepath.Join(certDir, "server.key"),
		ECDSACert:    filepath.Join(certDir, "server_ecdsa.crt"),
		ECDSAKey:     filepath.Join(certDir, "server_ecdsa.key"),
		GOSTCert:     filepath.Join(certDir, "server_gost.crt"),
		GOSTKey:      filepath.Join(certDir, "server_gost.key"),
		GOST2001Cert: filepath.Join(certDir, "server_gost2001.crt"),
		GOST2001Key:  filepath.Join(certDir, "server_gost2001.key"),
	}
	if !fuzzFileExists(caFile) {
		return nil, "testdata/tarantool/certs not populated; run testdata/tarantool/certs/gen.sh"
	}

	// Group ciphers by the cert pair they need; one listener per group. Ciphers
	// whose cert pair is absent are dropped.
	type group struct {
		certFile, keyFile string
		port              int
		ciphers           []string
	}
	var order []*group
	byCert := map[string]*group{}
	var dropped []string
	for _, c := range fuzzCiphers() {
		cf, kf := pickCertForCipher(certs, c)
		if !fuzzFileExists(cf) || !fuzzFileExists(kf) {
			dropped = append(dropped, c)
			continue
		}
		g := byCert[cf]
		if g == nil {
			g = &group{certFile: cf, keyFile: kf, port: fuzzFreePort()}
			byCert[cf] = g
			order = append(order, g)
		}
		g.ciphers = append(g.ciphers, c)
	}
	if len(order) == 0 {
		return nil, "testdata/tarantool/certs has no usable server cert; " +
			"run testdata/tarantool/certs/gen.sh"
	}

	workDir, err := os.MkdirTemp("/tmp", "ttee-fuzz-")
	if err != nil {
		return nil, fmt.Sprintf("mkdtemp: %v", err)
	}

	listeners := make([]fuzzListener, len(order))
	for i, g := range order {
		listeners[i] = fuzzListener{
			Port:     g.port,
			CertFile: g.certFile,
			KeyFile:  g.keyFile,
			Ciphers:  strings.Join(g.ciphers, ":"),
		}
	}

	cfgPath := filepath.Join(workDir, "config.yml")
	cfg, err := os.Create(cfgPath)
	if err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Sprintf("create config: %v", err)
	}
	err = fuzzConfigTmpl.Execute(cfg, struct {
		Listeners []fuzzListener
		WorkDir   string
	}{Listeners: listeners, WorkDir: workDir})
	_ = cfg.Close()
	if err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Sprintf("render config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "--name", "instance")
	cmd.Dir = workDir
	// Strip OPENSSL_CONF so a host gost-engine config cannot clash with EE's
	// statically-linked OpenSSL.
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "OPENSSL_CONF=") {
			env = append(env, kv)
		}
	}
	env = append(env, "TT_CONFIG="+cfgPath)
	cmd.Env = env
	var logbuf fuzzSyncBuffer
	cmd.Stdout = &logbuf
	cmd.Stderr = &logbuf

	fail := func(reasonf string, args ...any) (*fuzzEnv, string) {
		cancel()
		_ = cmd.Wait()
		_ = os.RemoveAll(workDir)
		msg := fmt.Sprintf(reasonf, args...)
		if tail := logbuf.String(); tail != "" {
			msg += "\n--- tarantool output ---\n" + tail
		}
		return nil, msg
	}

	if err := cmd.Start(); err != nil {
		return fail("start tarantool-ee: %v", err)
	}

	// Wait for the first listener, then connect+provision over it (with retry to
	// absorb the bootstrap-readiness race).
	addr := fmt.Sprintf("127.0.0.1:%d", order[0].port)
	if err := waitForTCP(addr, 30*time.Second); err != nil {
		return fail("tarantool-ee did not open %s: %v", addr, err)
	}
	primaryCipher := order[0].ciphers[0]
	primary, err := fuzzConnectRetry(caFile, order[0].port, primaryCipher, 30*time.Second)
	if err != nil {
		return fail("connect (%s) via gostls dialer: %v", primaryCipher, err)
	}
	if err := fuzzProvision(primary); err != nil {
		_ = primary.CloseGraceful()
		return fail("provision scratch space: %v", err)
	}

	// One connection per cipher; a suite that cannot handshake is dropped.
	pool := []fuzzEndpoint{{cipher: primaryCipher, conn: primary}}
	conns := []*tarantool.Connection{primary}
	for _, g := range order {
		for _, c := range g.ciphers {
			if c == primaryCipher {
				continue
			}
			conn, err := fuzzConnectRetry(caFile, g.port, c, 5*time.Second)
			if err != nil {
				dropped = append(dropped, c)
				continue
			}
			pool = append(pool, fuzzEndpoint{cipher: c, conn: conn})
			conns = append(conns, conn)
		}
	}

	connected := make([]string, len(pool))
	for i, ep := range pool {
		connected[i] = ep.cipher
	}
	fmt.Fprintf(os.Stderr, "[fuzz] cipher pool: %d connected %v\n", len(connected), connected)
	if len(dropped) > 0 {
		fmt.Fprintf(os.Stderr, "[fuzz] dropped %d suites (missing cert or no handshake): %v\n",
			len(dropped), dropped)
	}

	return &fuzzEnv{cancel: cancel, cmd: cmd, workDir: workDir, conns: conns, pool: pool}, ""
}

// fuzzConnectRetry dials the cipher on the port, retrying until the deadline.
func fuzzConnectRetry(caFile string, port int, cipher string,
	retry time.Duration) (*tarantool.Connection, error) {
	dialer := tlsdialer.OpenSSLDialer{
		// CN is "localhost"; dial the hostname so SNI + verification line up.
		Address:    fmt.Sprintf("localhost:%d", port),
		User:       "test",
		Password:   "test",
		SslCaFile:  caFile,
		SslCiphers: cipher,
		Backend:    gostls.New(),
	}
	deadline := time.Now().Add(retry)
	var lastErr error
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		// 15s per-request timeout: anything slower on loopback is a real hang.
		conn, err := tarantool.Connect(ctx, dialer, tarantool.Opts{Timeout: 15 * time.Second})
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("not ready within timeout: %w", lastErr)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func fuzzProvision(conn *tarantool.Connection) error {
	const ddl = `
local s = box.schema.space.create('` + fuzzSpaceName + `', {if_not_exists = true})
s:create_index('pk', {parts = {{1, 'unsigned'}}, if_not_exists = true})
return true`
	_, err := conn.Do(tarantool.NewEvalRequest(ddl)).Get()
	return err
}

func fuzzTeardown() {
	if fuzzShared == nil {
		return
	}
	for _, c := range fuzzShared.conns {
		_ = c.CloseGraceful()
	}
	if fuzzShared.cancel != nil {
		fuzzShared.cancel()
	}
	if fuzzShared.cmd != nil {
		_ = fuzzShared.cmd.Wait()
	}
	if fuzzShared.workDir != "" {
		_ = os.RemoveAll(fuzzShared.workDir)
	}
}

// TestMain owns teardown of the shared instance. It is tagged
// `tarantoolee && !openssl`, disjoint from the openssl integration TestMain.
func TestMain(m *testing.M) {
	code := m.Run()
	fuzzTeardown()
	os.Exit(code)
}

// fuzzCertDir resolves the cert dir relative to this source file.
func fuzzCertDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "testdata", "tarantool", "certs"))
}

func fuzzFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fuzzFreePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 3301
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// fuzzSyncBuffer is a goroutine-safe buffer for child-process output.
type fuzzSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *fuzzSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *fuzzSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ---- the fuzz target ---------------------------------------------------------

func FuzzRequestBatch(f *testing.F) {
	pool := fuzzEnvSetup(f)

	// (cipherSel, batch); cipherSel wraps over the pool.
	f.Add(uint8(0), []byte{})                                                // single ping
	f.Add(uint8(1), []byte{0})                                               // ping
	f.Add(uint8(2), []byte{1, 0x07, 0x00, 3, 'a', 'b', 'c'})                 // replace
	f.Add(uint8(3), []byte{2, 0x05, 0x00, 0x02, 1, 'x'})                     // insert
	f.Add(uint8(4), []byte{1, 0x09, 0x00, 0x00, 2, 'h', 'i', 3, 0x09, 0x00}) // replace then select
	f.Add(uint8(5), []byte{1, 1, 0, 0, 1, 'v', 4, 1, 0, 0, 2, 'w', 5, 1, 0}) // repl, upd, del
	f.Add(uint8(6), bytes.Repeat([]byte{1, 0x11, 0x00, 0x02, 5, 'z'}, 24))   // many replaces
	f.Add(uint8(7), []byte{7, 0x04, 0x00})                                   // eval-echo

	f.Fuzz(func(t *testing.T, cipherSel uint8, data []byte) {
		ep := pool[int(cipherSel)%len(pool)]
		conn := ep.conn
		reqs := buildFuzzBatch(data)

		// Fire the whole batch (pipelined), then collect.
		futs := make([]tarantool.Future, len(reqs))
		for i, r := range reqs {
			futs[i] = conn.Do(r)
		}
		for i, fut := range futs {
			if _, err := fut.Get(); err != nil && isTransportFailure(err) {
				require.NoErrorf(t, err, "transport failure on batched request %d/%d over %s",
					i+1, len(futs), ep.cipher)
			}
		}

		fuzzCanary(t, conn, ep.cipher)
	})
}

// isTransportFailure distinguishes a client/transport failure (a finding) from
// a server box error (a valid response to a garbage request).
func isTransportFailure(err error) bool {
	var se tarantool.ServerError
	if errors.As(err, &se) {
		return false
	}
	return errors.Is(err, tarantool.ErrProtocolError) ||
		errors.Is(err, tarantool.ErrConnectionClosed) ||
		errors.Is(err, tarantool.ErrConnectionShutdown) ||
		errors.Is(err, tarantool.ErrIoError) ||
		errors.Is(err, tarantool.ErrTimeouted)
}

// fuzzCanary replaces and re-selects a fixed tuple; a mismatch or error means
// the batch left the connection's request/response framing desynced.
func fuzzCanary(t *testing.T, conn *tarantool.Connection, cipher string) {
	t.Helper()
	_, err := conn.Do(tarantool.NewReplaceRequest(fuzzSpaceName).
		Tuple([]any{fuzzCanaryKey, fuzzCanaryVal})).Get()
	require.NoErrorf(t, err,
		"canary replace failed over %s (connection unusable after batch)", cipher)
	data, err := conn.Do(tarantool.NewSelectRequest(fuzzSpaceName).
		Index("pk").
		Iterator(tarantool.IterEq).
		Key([]any{fuzzCanaryKey}).
		Limit(1)).Get()
	require.NoErrorf(t, err, "canary select failed over %s", cipher)
	require.Lenf(t, data, 1, "canary select over %s: response desync", cipher)

	tup, ok := data[0].([]any)
	require.Truef(t, ok && len(tup) >= 2, "canary tuple malformed over %s: %#v", cipher, data[0])

	s, _ := tup[1].(string)
	require.Equalf(t, fuzzCanaryVal, s, "canary value mismatch over %s", cipher)
}

// ---- fuzz input decoding -----------------------------------------------------

// buildFuzzBatch decodes fuzz bytes into a bounded batch: each step's first
// byte selects the opcode, the rest supply keys and values. An exhausted input
// yields a single ping.
func buildFuzzBatch(data []byte) []tarantool.Request {
	r := bytes.NewReader(data)
	reqs := make([]tarantool.Request, 0, 8)

	for len(reqs) < fuzzMaxOps {
		op, err := r.ReadByte()
		if err != nil {
			break
		}
		switch op % 8 {
		case 0:
			reqs = append(reqs, tarantool.NewPingRequest())
		case 1:
			k := fuzzKey(r)
			reqs = append(reqs, tarantool.NewReplaceRequest(fuzzSpaceName).
				Tuple([]any{k, fuzzValue(r)}))
		case 2:
			k := fuzzKey(r)
			reqs = append(reqs, tarantool.NewInsertRequest(fuzzSpaceName).
				Tuple([]any{k, fuzzValue(r)}))
		case 3:
			k := fuzzKey(r)
			reqs = append(reqs, tarantool.NewSelectRequest(fuzzSpaceName).
				Index("pk").
				Iterator(tarantool.IterEq).
				Key([]any{k}).
				Limit(fuzzLimit(r)))
		case 4:
			k := fuzzKey(r)
			ops := tarantool.NewOperations().Assign(1, fuzzValue(r))
			reqs = append(reqs, tarantool.NewUpdateRequest(fuzzSpaceName).
				Key([]any{k}).
				Operations(ops))
		case 5:
			k := fuzzKey(r)
			reqs = append(reqs, tarantool.NewDeleteRequest(fuzzSpaceName).
				Key([]any{k}))
		case 6:
			k := fuzzKey(r)
			v := fuzzValue(r)
			ops := tarantool.NewOperations().Assign(1, v)
			reqs = append(reqs, tarantool.NewUpsertRequest(fuzzSpaceName).
				Tuple([]any{k, v}).
				Operations(ops))
		case 7:
			// Fixed expression, fuzzed args: args are msgpack (no Lua injection)
			// and "return ..." runs no loops (cannot hang the instance).
			reqs = append(reqs, tarantool.NewEvalRequest("return ...").
				Args([]any{fuzzValue(r), fuzzKey(r)}))
		}
	}

	if len(reqs) == 0 {
		reqs = append(reqs, tarantool.NewPingRequest())
	}
	return reqs
}

// fuzzKey reads a primary key bounded to [0, fuzzKeyMod).
func fuzzKey(r *bytes.Reader) uint64 {
	var k uint64
	for i := 0; i < 2; i++ {
		b, err := r.ReadByte()
		if err != nil {
			break
		}
		k = k<<8 | uint64(b)
	}
	return k % fuzzKeyMod
}

func fuzzLimit(r *bytes.Reader) uint32 {
	b, err := r.ReadByte()
	if err != nil {
		return 1
	}
	return uint32(b) * 4
}

// fuzzValue reads one tuple field whose type is chosen by a tag byte.
func fuzzValue(r *bytes.Reader) any {
	tag, err := r.ReadByte()
	if err != nil {
		return nil
	}
	switch tag % 7 {
	case 0:
		return string(fuzzBlob(r))
	case 1:
		return fuzzBlob(r)
	case 2:
		return int64(fuzzKey(r)) - fuzzKeyMod/2
	case 3:
		return float64(int64(fuzzKey(r))) / 7.0
	case 4:
		b, _ := r.ReadByte()
		return b%2 == 0
	case 5:
		return nil
	default:
		return []any{int64(fuzzKey(r)), string(fuzzBlob(r))}
	}
}

// fuzzBlob reads a length-prefixed byte slice capped at fuzzMaxField.
func fuzzBlob(r *bytes.Reader) []byte {
	n, err := r.ReadByte()
	if err != nil {
		return nil
	}
	size := int(n)
	if size > fuzzMaxField {
		size = fuzzMaxField
	}
	out := make([]byte, 0, size)
	for i := 0; i < size; i++ {
		b, err := r.ReadByte()
		if err != nil {
			break
		}
		out = append(out, b)
	}
	return out
}
