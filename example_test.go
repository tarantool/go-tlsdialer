package tlsdialer_test

import (
	"context"
	"fmt"
	"time"

	"github.com/tarantool/go-tarantool/v2"
	"github.com/tarantool/go-tarantool/v2/test_helpers"
	"github.com/tarantool/go-tlsdialer"
)

func ExampleOpenSSLDialer() {
	dialer := tlsdialer.OpenSSLDialer{
		Address:  "127.0.0.1:3014",
		User:     "test",
		Password: "test",
	}
	opts := tarantool.Opts{
		Timeout: 5 * time.Second,
	}

	// Start Tarantool instance with enabled ssl and set keys and credentials.
	listen := "127.0.0.1:3014" + "?transport=ssl&"
	listen += "ssl_key_file=testdata/localhost.key&"
	listen += "ssl_cert_file=testdata/localhost.crt"

	inst, err := test_helpers.StartTarantool(
		test_helpers.StartOpts{
			Dialer:       dialer,
			InitScript:   "testdata/config.lua",
			Listen:       listen,
			SslCertsDir:  "testdata",
			WaitStart:    100 * time.Millisecond,
			ConnectRetry: 10,
			RetryTimeout: 500 * time.Millisecond,
		},
	)
	if err != nil {
		fmt.Printf("Failed to create a Tarantool instance: %s", err)
		return
	}
	defer test_helpers.StopTarantool(inst)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	conn, err := tarantool.Connect(ctx, dialer, opts)
	if err != nil {
		fmt.Printf("Failed to create an example connection: %s", err)
		return
	}

	// Use the connection.
	data, err := conn.Do(tarantool.NewPingRequest()).Get()
	if err != nil {
		fmt.Printf("Error: %s", err)
	} else {
		fmt.Printf("Data: %v", data)
	}

	// Output:
	// Data: []
}
