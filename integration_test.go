package tlsdialer_test

import (
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/tarantool/go-tarantool/v2"
	"github.com/tarantool/go-tarantool/v2/test_helpers"
	"github.com/tarantool/go-tlsdialer"
)

var server = "127.0.0.1:3013"

var startOpts = test_helpers.StartOpts{
	Dialer:       dialer,
	InitScript:   "testdata/config.lua",
	Listen:       server,
	WaitStart:    100 * time.Millisecond,
	ConnectRetry: 10,
	RetryTimeout: 500 * time.Millisecond,
}

var dialer = tarantool.NetDialer{
	Address:  server,
	User:     "test",
	Password: "test",
}

func serverTt(serverOpts tlsdialer.SslTestOpts,
	auth tarantool.Auth) (test_helpers.TarantoolInstance, error) {
	listen := ttHost + "?transport=ssl&"

	key := serverOpts.KeyFile
	if key != "" {
		listen += fmt.Sprintf("ssl_key_file=%s&", key)
	}

	cert := serverOpts.CertFile
	if cert != "" {
		listen += fmt.Sprintf("ssl_cert_file=%s&", cert)
	}

	ca := serverOpts.CaFile
	if ca != "" {
		listen += fmt.Sprintf("ssl_ca_file=%s&", ca)
	}

	ciphers := serverOpts.Ciphers
	if ciphers != "" {
		listen += fmt.Sprintf("ssl_ciphers=%s&", ciphers)
	}

	password := serverOpts.Password
	if password != "" {
		listen += fmt.Sprintf("ssl_password=%s&", password)
	}

	passwordFile := serverOpts.PasswordFile
	if passwordFile != "" {
		listen += fmt.Sprintf("ssl_password_file=%s&", passwordFile)
	}

	listen = listen[:len(listen)-1]

	return test_helpers.StartTarantool(
		test_helpers.StartOpts{
			Dialer: tlsdialer.OpenSSLDialer{
				Address:         ttHost,
				Auth:            auth,
				User:            "test",
				Password:        "test",
				SslKeyFile:      serverOpts.KeyFile,
				SslCertFile:     serverOpts.CertFile,
				SslCaFile:       serverOpts.CaFile,
				SslCiphers:      serverOpts.Ciphers,
				SslPassword:     serverOpts.Password,
				SslPasswordFile: serverOpts.PasswordFile,
			},
			Auth:         auth,
			InitScript:   "testdata/config.lua",
			Listen:       listen,
			SslCertsDir:  "testdata",
			WaitStart:    100 * time.Millisecond,
			ConnectRetry: 10,
			RetryTimeout: 500 * time.Millisecond,
		},
	)
}

func serverTtStop(inst test_helpers.TarantoolInstance) {
	test_helpers.StopTarantoolWithCleanup(inst)
}

func checkTtConn(dialer tarantool.Dialer) error {
	ctx, cancel := test_helpers.GetConnectContext()
	defer cancel()
	conn, err := tarantool.Connect(ctx, dialer, tarantool.Opts{
		Timeout:    500 * time.Millisecond,
		SkipSchema: true,
	})
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func assertConnectionTtFail(t testing.TB, serverOpts tlsdialer.SslTestOpts,
	dialer tlsdialer.OpenSSLDialer) {
	t.Helper()

	inst, err := serverTt(serverOpts, tarantool.AutoAuth)
	defer serverTtStop(inst)
	if err != nil {
		t.Fatalf("An unexpected server error %q", err.Error())
	}

	err = checkTtConn(dialer)
	if err == nil {
		t.Errorf("An unexpected connection to the server")
	}
}

func assertConnectionTtOk(t testing.TB, serverOpts tlsdialer.SslTestOpts,
	dialer tlsdialer.OpenSSLDialer) {
	t.Helper()

	inst, err := serverTt(serverOpts, tarantool.AutoAuth)
	defer serverTtStop(inst)
	if err != nil {
		t.Fatalf("An unexpected server error %q", err.Error())
	}

	err = checkTtConn(dialer)
	if err != nil {
		t.Errorf("An unexpected connection error %q", err.Error())
	}
}

type sslTest struct {
	name       string
	ok         bool
	serverOpts tlsdialer.SslTestOpts
	clientOpts tlsdialer.SslTestOpts
}

/*
Requirements from Tarantool Enterprise Edition manual:
https://www.tarantool.io/ru/enterprise_doc/security/#configuration

For a server:
KeyFile - mandatory
CertFile - mandatory
CaFile - optional
Ciphers - optional

For a client:
KeyFile - optional, mandatory if server.CaFile set
CertFile - optional, mandatory if server.CaFile set
CaFile - optional,
Ciphers - optional.
*/
var sslTests = []sslTest{
	{
		"key_crt_server",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
		},
		tlsdialer.SslTestOpts{},
	},
	{
		"key_crt_server_and_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
		},
	},
	{
		"key_crt_ca_server",
		false,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{},
	},
	{
		"key_crt_ca_server_key_crt_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
		},
	},
	{
		"key_crt_ca_server_and_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
	},
	{
		"key_crt_ca_server_and_client_invalid_path_key",
		false,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "any_invalid_path",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
	},
	{
		"key_crt_ca_server_and_client_invalid_path_crt",
		false,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "any_invalid_path",
			CaFile:   "testdata/ca.crt",
		},
	},
	{
		"key_crt_ca_server_and_client_invalid_path_ca",
		false,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "any_invalid_path",
		},
	},
	{
		"key_crt_ca_server_and_client_empty_key",
		false,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/empty",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
	},
	{
		"key_crt_ca_server_and_client_empty_crt",
		false,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/empty",
			CaFile:   "testdata/ca.crt",
		},
	},
	{
		"key_crt_ca_server_and_client_empty_ca",
		false,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/empty",
		},
	},
	{
		"key_crt_server_and_key_crt_ca_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
	},
	{
		"key_crt_ca_ciphers_server_key_crt_ca_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
			Ciphers:  "ECDHE-RSA-AES256-GCM-SHA384",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
	},
	{
		"key_crt_ca_ciphers_server_and_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
			Ciphers:  "ECDHE-RSA-AES256-GCM-SHA384",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
			Ciphers:  "ECDHE-RSA-AES256-GCM-SHA384",
		},
	},
	{
		"non_equal_ciphers_client",
		false,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
			Ciphers:  "ECDHE-RSA-AES256-GCM-SHA384",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
			Ciphers:  "TLS_AES_128_GCM_SHA256",
		},
	},
	{
		"pass_key_encrypt_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.enc.key",
			CertFile: "testdata/localhost.crt",
			Password: "mysslpassword",
		},
	},
	{
		"passfile_key_encrypt_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:      "testdata/localhost.enc.key",
			CertFile:     "testdata/localhost.crt",
			PasswordFile: "testdata/passwords",
		},
	},
	{
		"pass_and_passfile_key_encrypt_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:      "testdata/localhost.enc.key",
			CertFile:     "testdata/localhost.crt",
			Password:     "mysslpassword",
			PasswordFile: "testdata/passwords",
		},
	},
	{
		"inv_pass_and_passfile_key_encrypt_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:      "testdata/localhost.enc.key",
			CertFile:     "testdata/localhost.crt",
			Password:     "invalidpassword",
			PasswordFile: "testdata/passwords",
		},
	},
	{
		"pass_and_inv_passfile_key_encrypt_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:      "testdata/localhost.enc.key",
			CertFile:     "testdata/localhost.crt",
			Password:     "mysslpassword",
			PasswordFile: "testdata/invalidpasswords",
		},
	},
	{
		"pass_and_not_existing_passfile_key_encrypt_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:      "testdata/localhost.enc.key",
			CertFile:     "testdata/localhost.crt",
			Password:     "mysslpassword",
			PasswordFile: "testdata/notafile",
		},
	},
	{
		"inv_pass_and_inv_passfile_key_encrypt_client",
		false,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:      "testdata/localhost.enc.key",
			CertFile:     "testdata/localhost.crt",
			Password:     "invalidpassword",
			PasswordFile: "testdata/invalidpasswords",
		},
	},
	{
		"not_existing_passfile_key_encrypt_client",
		false,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:      "testdata/localhost.enc.key",
			CertFile:     "testdata/localhost.crt",
			PasswordFile: "testdata/notafile",
		},
	},
	{
		"no_pass_key_encrypt_client",
		false,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.enc.key",
			CertFile: "testdata/localhost.crt",
		},
	},
	{
		"pass_key_non_encrypt_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			Password: "invalidpassword",
		},
	},
	{
		"passfile_key_non_encrypt_client",
		true,
		tlsdialer.SslTestOpts{
			KeyFile:  "testdata/localhost.key",
			CertFile: "testdata/localhost.crt",
			CaFile:   "testdata/ca.crt",
		},
		tlsdialer.SslTestOpts{
			KeyFile:      "testdata/localhost.key",
			CertFile:     "testdata/localhost.crt",
			PasswordFile: "testdata/invalidpasswords",
		},
	},
}

func makeOpenSslDialer(opts tlsdialer.SslTestOpts) tlsdialer.OpenSSLDialer {
	return tlsdialer.OpenSSLDialer{
		Address:         ttHost,
		User:            "test",
		Password:        "test",
		SslKeyFile:      opts.KeyFile,
		SslCertFile:     opts.CertFile,
		SslCaFile:       opts.CaFile,
		SslCiphers:      opts.Ciphers,
		SslPassword:     opts.Password,
		SslPasswordFile: opts.PasswordFile,
	}
}

func TestSslOpts(t *testing.T) {
	for _, test := range sslTests {
		dialer := makeOpenSslDialer(test.clientOpts)
		if test.ok {
			t.Run("ok_tt_"+test.name, func(t *testing.T) {
				assertConnectionTtOk(t, test.serverOpts, dialer)
			})
		} else {
			t.Run("fail_tt_"+test.name, func(t *testing.T) {
				assertConnectionTtFail(t, test.serverOpts, dialer)
			})
		}
	}
}

func TestOpts_PapSha256Auth(t *testing.T) {
	isLess, err := test_helpers.IsTarantoolVersionLess(2, 11, 0)
	if err != nil {
		t.Fatalf("Could not check Tarantool version: %s", err)
	}
	if isLess {
		t.Skip("Skipping test for Tarantool without pap-sha256 support")
	}

	sslOpts := tlsdialer.SslTestOpts{
		KeyFile:  "testdata/localhost.key",
		CertFile: "testdata/localhost.crt",
	}

	inst, err := serverTt(sslOpts, tarantool.PapSha256Auth)
	defer serverTtStop(inst)
	if err != nil {
		t.Fatalf("An unexpected server error %q", err.Error())
	}

	client := tlsdialer.OpenSSLDialer{
		Address:              ttHost,
		Auth:                 tarantool.PapSha256Auth,
		User:                 "test",
		Password:             "test",
		RequiredProtocolInfo: tarantool.ProtocolInfo{},
		SslKeyFile:           sslOpts.KeyFile,
		SslCertFile:          sslOpts.CertFile,
	}

	conn := test_helpers.ConnectWithValidation(t, client, opts)
	conn.Close()

	client.Auth = tarantool.AutoAuth
	conn = test_helpers.ConnectWithValidation(t, client, opts)
	conn.Close()
}

func TestReadDeadline(t *testing.T) {
	sslOpts := tlsdialer.SslTestOpts{
		KeyFile:  "testdata/localhost.key",
		CertFile: "testdata/localhost.crt",
	}

	inst, err := serverTt(sslOpts, tarantool.AutoAuth)
	defer serverTtStop(inst)
	if err != nil {
		t.Fatalf("An unexpected server error %q", err.Error())
	}

	dialer := tlsdialer.OpenSSLDialer{
		Address:  ttHost,
		User:     testDialUser,
		Password: testDialPass,
	}

	ioTimeout := 5 * time.Second

	ctx, cancel := test_helpers.GetConnectContext()
	defer cancel()
	conn, err := dialer.Dial(ctx, tarantool.DialOpts{
		IoTimeout: ioTimeout,
	})
	if conn == nil {
		t.Fatalf("Unable to connect: %s", err)
	}
	defer conn.Close()

	largeMessage := [1024 * 1024]byte{}

	timeStart := time.Now()
	n, err := conn.Read(largeMessage[:])
	timeEnd := time.Now()

	if n != 0 || err == nil {
		t.Errorf("Successful read, expected i/o timeout")
	}
	eps := 500 * time.Millisecond
	if timeStart.Add(ioTimeout).After(timeEnd.Add(eps)) ||
		timeStart.Add(ioTimeout).Before(timeEnd.Add(-eps)) {
		t.Errorf("Incorrect timeout while reading")
	}
}

// runTestMain is a body of TestMain function
// (see https://pkg.go.dev/testing#hdr-Main).
// Using defer + os.Exit is not works so TestMain body
// is a separate function, see
// https://stackoverflow.com/questions/27629380/how-to-exit-a-go-program-honoring-deferred-calls
func runTestMain(m *testing.M) int {
	// Tarantool supports streams and interactive transactions since version 2.10.0
	isStreamUnsupported, err := test_helpers.IsTarantoolVersionLess(2, 10, 0)
	if err != nil {
		log.Fatalf("Could not check the Tarantool version: %s", err)
	}

	startOpts.MemtxUseMvccEngine = !isStreamUnsupported

	inst, err := test_helpers.StartTarantool(startOpts)
	defer test_helpers.StopTarantoolWithCleanup(inst)

	if err != nil {
		log.Printf("Failed to prepare test tarantool: %s", err)
		return 1
	}

	return m.Run()
}

func TestMain(m *testing.M) {
	code := runTestMain(m)
	os.Exit(code)
}
