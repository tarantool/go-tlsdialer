package integration_test

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-iproto"

	"github.com/tarantool/go-tarantool/v3"
	"github.com/tarantool/go-tarantool/v3/test_helpers"
)

func genSalt() [64]byte {
	salt := [64]byte{}
	for i := 0; i < 44; i++ {
		salt[i] = 'a'
	}
	return salt
}

var (
	testDialUser    = "test"
	testDialPass    = "test"
	testDialVersion = [64]byte{'t', 'e', 's', 't'}

	// Salt with end zeros.
	testDialSalt = genSalt()

	idRequestExpected = []byte{
		0xce, 0x00, 0x00, 0x00, 31, // Length.
		0x82, // Header map.
		0x00, 0x49,
		0x01, 0xce, 0x00, 0x00, 0x00, 0x00,

		0x82, // Data map.
		0x54,
		0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, // Version.
		0x55,
		0x99, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0b, 0x0c, // Features.
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
