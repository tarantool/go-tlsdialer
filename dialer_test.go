package tlsdialer_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-iproto"
	"github.com/tarantool/go-openssl"
	"github.com/tarantool/go-tlsdialer"

	"github.com/tarantool/go-tarantool/v2"
	"github.com/tarantool/go-tarantool/v2/test_helpers"
)

const ttHost = "127.0.0.1:3014"

func genSalt() [64]byte {
	salt := [64]byte{}
	for i := 0; i < 44; i++ {
		salt[i] = 'a'
	}
	return salt
}

var (
	opts = tarantool.Opts{
		Timeout: 5 * time.Second,
	}

	testDialUser    = "test"
	testDialPass    = "test"
	testDialVersion = [64]byte{'t', 'e', 's', 't'}

	// Salt with end zeros.
	testDialSalt = genSalt()

	idRequestExpected = []byte{
		0xce, 0x00, 0x00, 0x00, 29, // Length.
		0x82, // Header map.
		0x00, 0x49,
		0x01, 0xce, 0x00, 0x00, 0x00, 0x00,

		0x82, // Data map.
		0x54,
		0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, // Version.
		0x55,
		0x97, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Features.
	}

	idResponseTyped = tarantool.ProtocolInfo{
		Version:  6,
		Features: []iproto.Feature{iproto.Feature(1), iproto.Feature(21)},
		Auth:     tarantool.ChapSha1Auth,
	}

	idResponse = []byte{
		0xce, 0x00, 0x00, 0x00, 37, // Length.
		0x83, // Header map.
		0x00, 0xce, 0x00, 0x00, 0x00, 0x00,
		0x01, 0xce, 0x00, 0x00, 0x00, 0x00,
		0x05, 0xce, 0x00, 0x00, 0x00, 0x61,

		0x83, // Data map.
		0x54,
		0x06, // Version.
		0x55,
		0x92, 0x01, 0x15, // Features.
		0x5b,
		0xa9, 'c', 'h', 'a', 'p', '-', 's', 'h', 'a', '1',
	}

	idResponseNotSupported = []byte{
		0xce, 0x00, 0x00, 0x00, 25, // Length.
		0x83, // Header map.
		0x00, 0xce, 0x00, 0x00, 0x80, 0x30,
		0x01, 0xce, 0x00, 0x00, 0x00, 0x00,
		0x05, 0xce, 0x00, 0x00, 0x00, 0x61,
		0x81,
		0x31,
		0xa3, 'e', 'r', 'r',
	}

	authRequestExpectedChapSha1 = []byte{
		0xce, 0x00, 0x00, 0x00, 57, // Length.
		0x82, // Header map.
		0x00, 0x07,
		0x01, 0xce, 0x00, 0x00, 0x00, 0x00,

		0x82, // Data map.
		0xce, 0x00, 0x00, 0x00, 0x23,
		0xa4, 't', 'e', 's', 't', // Login.
		0xce, 0x00, 0x00, 0x00, 0x21,
		0x92, // Tuple.
		0xa9, 'c', 'h', 'a', 'p', '-', 's', 'h', 'a', '1',

		// Scramble.
		0xb4, 0x1b, 0xd4, 0x20, 0x45, 0x73, 0x22,
		0xcf, 0xab, 0x05, 0x03, 0xf3, 0x89, 0x4b,
		0xfe, 0xc7, 0x24, 0x5a, 0xe6, 0xe8, 0x31,
	}

	authRequestExpectedPapSha256 = []byte{
		0xce, 0x00, 0x00, 0x00, 0x2a, // Length.
		0x82, // Header map.
		0x00, 0x07,
		0x01, 0xce, 0x00, 0x00, 0x00, 0x00,

		0x82, // Data map.
		0xce, 0x00, 0x00, 0x00, 0x23,
		0xa4, 't', 'e', 's', 't', // Login.
		0xce, 0x00, 0x00, 0x00, 0x21,
		0x92, // Tuple.
		0xaa, 'p', 'a', 'p', '-', 's', 'h', 'a', '2', '5', '6',
		0xa4, 't', 'e', 's', 't',
	}

	okResponse = []byte{
		0xce, 0x00, 0x00, 0x00, 19, // Length.
		0x83, // Header map.
		0x00, 0xce, 0x00, 0x00, 0x00, 0x00,
		0x01, 0xce, 0x00, 0x00, 0x00, 0x00,
		0x05, 0xce, 0x00, 0x00, 0x00, 0x61,
	}

	errResponse = []byte{0xce}
)

type testDialOpts struct {
	name                 string
	address              string
	wantErr              bool
	expectedErr          string
	expectedProtocolInfo tarantool.ProtocolInfo

	// These options configure the behavior of the server.
	isErrGreeting   bool
	isErrID         bool
	isIDUnsupported bool
	isPapSha256Auth bool
	isErrAuth       bool
}

type dialServerActual struct {
	IDRequest   []byte
	AuthRequest []byte
}

func testDialAccept(opts testDialOpts, l net.Listener) chan dialServerActual {
	ch := make(chan dialServerActual, 1)

	go func() {
		client, err := l.Accept()
		if err != nil {
			return
		}
		defer client.Close()
		if opts.isErrGreeting {
			_, _ = client.Write(errResponse)
			return
		}
		// Write greeting.
		if _, err = client.Write(testDialVersion[:]); err != nil {
			return
		}
		if _, err = client.Write(testDialSalt[:]); err != nil {
			return
		}

		// Read Id request.
		idRequestActual := make([]byte, len(idRequestExpected))
		if _, err = client.Read(idRequestActual); err != nil {
			return
		}

		// Make Id response.
		switch {
		case opts.isErrID:
			_, err = client.Write(errResponse)
		case opts.isIDUnsupported:
			_, err = client.Write(idResponseNotSupported)
		default:
			_, err = client.Write(idResponse)
		}
		if err != nil {
			return
		}

		// Read Auth request.
		authRequestExpected := authRequestExpectedChapSha1
		if opts.isPapSha256Auth {
			authRequestExpected = authRequestExpectedPapSha256
		}
		authRequestActual := make([]byte, len(authRequestExpected))
		if _, err = client.Read(authRequestActual); err != nil {
			return
		}

		// Make Auth response.
		if opts.isErrAuth {
			_, err = client.Write(errResponse)
		} else {
			_, err = client.Write(okResponse)
		}
		if err != nil {
			return
		}

		ch <- dialServerActual{
			IDRequest:   idRequestActual,
			AuthRequest: authRequestActual,
		}
	}()

	return ch
}

func testDialer(t *testing.T, l net.Listener, dialer tarantool.Dialer,
	opts testDialOpts) {
	ctx, cancel := test_helpers.GetConnectContext()
	defer cancel()
	ch := testDialAccept(opts, l)
	conn, err := dialer.Dial(ctx, tarantool.DialOpts{
		IoTimeout: time.Second * 2,
	})
	if opts.wantErr {
		require.Error(t, err)
		require.Contains(t, err.Error(), opts.expectedErr)
		return
	}
	require.NoError(t, err)
	require.Equal(t, opts.expectedProtocolInfo, conn.ProtocolInfo())
	require.Equal(t, testDialVersion[:], []byte(conn.Greeting().Version))
	require.Equal(t, testDialSalt[:44], []byte(conn.Greeting().Salt))

	actual := <-ch
	require.Equal(t, idRequestExpected, actual.IDRequest)

	authRequestExpected := authRequestExpectedChapSha1
	if opts.isPapSha256Auth {
		authRequestExpected = authRequestExpectedPapSha256
	}
	require.Equal(t, authRequestExpected, actual.AuthRequest)
	conn.Close()
}

func createSslListener(t *testing.T, opts tlsdialer.SslTestOpts) net.Listener {
	ctx, err := tlsdialer.SslCreateContext(opts)
	require.NoError(t, err)
	l, err := openssl.Listen("tcp", "127.0.0.1:0", ctx)
	require.NoError(t, err)
	return l
}

func TestOpenSslDialer_Dial_opts(t *testing.T) {
	for _, test := range sslTests {
		t.Run(test.name, func(t *testing.T) {
			l := createSslListener(t, test.serverOpts)
			defer l.Close()
			addr := l.Addr().String()

			dialer := tlsdialer.OpenSSLDialer{
				Address:         addr,
				User:            testDialUser,
				Password:        testDialPass,
				SslKeyFile:      test.clientOpts.KeyFile,
				SslCertFile:     test.clientOpts.CertFile,
				SslCaFile:       test.clientOpts.CaFile,
				SslCiphers:      test.clientOpts.Ciphers,
				SslPassword:     test.clientOpts.Password,
				SslPasswordFile: test.clientOpts.PasswordFile,
			}
			testDialer(t, l, dialer, testDialOpts{
				wantErr:              !test.ok,
				expectedProtocolInfo: idResponseTyped.Clone(),
			})
		})
	}
}

func TestOpenSslDialer_Dial_basic(t *testing.T) {
	l := createSslListener(t, tlsdialer.SslTestOpts{
		KeyFile:  "testdata/localhost.key",
		CertFile: "testdata/localhost.crt",
	})

	defer l.Close()
	addr := l.Addr().String()

	dialer := tlsdialer.OpenSSLDialer{
		Address:  addr,
		User:     testDialUser,
		Password: testDialPass,
	}

	cases := []testDialOpts{
		{
			name:                 "all is ok",
			expectedProtocolInfo: idResponseTyped.Clone(),
		},
		{
			name:                 "id request unsupported",
			expectedProtocolInfo: tarantool.ProtocolInfo{},
			isIDUnsupported:      true,
		},
		{
			name:          "greeting response error",
			wantErr:       true,
			expectedErr:   "failed to read greeting",
			isErrGreeting: true,
		},
		{
			name:        "id response error",
			wantErr:     true,
			expectedErr: "failed to identify",
			isErrID:     true,
		},
		{
			name:        "auth response error",
			wantErr:     true,
			expectedErr: "failed to authenticate",
			isErrAuth:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testDialer(t, l, dialer, tc)
		})
	}
}

func TestOpenSslDialer_Dial_requirements(t *testing.T) {
	l := createSslListener(t, tlsdialer.SslTestOpts{
		KeyFile:  "testdata/localhost.key",
		CertFile: "testdata/localhost.crt",
	})

	defer l.Close()
	addr := l.Addr().String()

	dialer := tlsdialer.OpenSSLDialer{
		Address:  addr,
		User:     testDialUser,
		Password: testDialPass,
		RequiredProtocolInfo: tarantool.ProtocolInfo{
			Features: []iproto.Feature{42},
		},
	}

	testDialAccept(testDialOpts{}, l)
	ctx, cancel := test_helpers.GetConnectContext()
	defer cancel()
	conn, err := dialer.Dial(ctx, tarantool.DialOpts{})
	if err == nil {
		conn.Close()
	}
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid server protocol")
}

func TestOpenSslDialer_Dial_papSha256Auth(t *testing.T) {
	l := createSslListener(t, tlsdialer.SslTestOpts{
		KeyFile:  "testdata/localhost.key",
		CertFile: "testdata/localhost.crt",
	})

	defer l.Close()
	addr := l.Addr().String()

	dialer := tlsdialer.OpenSSLDialer{
		Address:  addr,
		User:     testDialUser,
		Password: testDialPass,
		Auth:     tarantool.PapSha256Auth,
	}

	// Response from the server.
	protocol := idResponseTyped.Clone()
	protocol.Auth = tarantool.ChapSha1Auth

	testDialer(t, l, dialer, testDialOpts{
		expectedProtocolInfo: protocol,
		isPapSha256Auth:      true,
	})
}

func TestOpenSslDialer_Dial_ctx_cancel(t *testing.T) {
	serverOpts := tlsdialer.SslTestOpts{
		KeyFile:  "testdata/localhost.key",
		CertFile: "testdata/localhost.crt",
		CaFile:   "testdata/ca.crt",
		Ciphers:  "ECDHE-RSA-AES256-GCM-SHA384",
	}
	clientOpts := tlsdialer.SslTestOpts{
		KeyFile:  "testdata/localhost.key",
		CertFile: "testdata/localhost.crt",
		CaFile:   "testdata/ca.crt",
		Ciphers:  "ECDHE-RSA-AES256-GCM-SHA384",
	}

	l := createSslListener(t, serverOpts)
	defer l.Close()
	addr := l.Addr().String()
	testDialAccept(testDialOpts{}, l)

	dialer := tlsdialer.OpenSSLDialer{
		Address:         addr,
		User:            testDialUser,
		Password:        testDialPass,
		SslKeyFile:      clientOpts.KeyFile,
		SslCertFile:     clientOpts.CertFile,
		SslCaFile:       clientOpts.CaFile,
		SslCiphers:      clientOpts.Ciphers,
		SslPassword:     clientOpts.Password,
		SslPasswordFile: clientOpts.PasswordFile,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := dialer.Dial(ctx, tarantool.DialOpts{})
	if err == nil {
		conn.Close()
	}
	require.Error(t, err)
}

func TestAddressFormat_tcp(t *testing.T) {
	l := createSslListener(t, tlsdialer.SslTestOpts{
		KeyFile:  "testdata/localhost.key",
		CertFile: "testdata/localhost.crt",
	})

	defer l.Close()
	addr := l.Addr().String()

	protocolInfo := idResponseTyped.Clone()

	cases := []testDialOpts{
		{
			name:                 "base",
			address:              addr,
			expectedProtocolInfo: protocolInfo,
		},
		{
			name:                 "tcp://",
			address:              fmt.Sprintf("tcp://%s", addr),
			expectedProtocolInfo: protocolInfo,
		},
		{
			name:                 "tcp:",
			address:              fmt.Sprintf("tcp:%s", addr),
			expectedProtocolInfo: protocolInfo,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialer := tlsdialer.OpenSSLDialer{
				Address:  tc.address,
				User:     testDialUser,
				Password: testDialPass,
			}

			testDialer(t, l, dialer, tc)
		})
	}
}
