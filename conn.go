package tlsdialer

import (
	"errors"
	"io"
	"net"

	"github.com/tarantool/go-tarantool/v2"
)

type ttConn struct {
	net    net.Conn
	reader io.Reader
	writer writeFlusher
}

// writeFlusher is the interface that groups the basic Write and Flush methods.
type writeFlusher interface {
	io.Writer
	Flush() error
}

// Addr makes ttConn satisfy the Conn interface.
func (c *ttConn) Addr() net.Addr {
	return c.net.RemoteAddr()
}

// Read makes ttConn satisfy the Conn interface.
func (c *ttConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// Write makes ttConn satisfy the Conn interface.
func (c *ttConn) Write(p []byte) (int, error) {
	var (
		l   int
		err error
	)

	if l, err = c.writer.Write(p); err != nil {
		return l, err
	} else if l != len(p) {
		return l, errors.New("wrong length written")
	}
	return l, nil
}

// Flush makes ttConn satisfy the Conn interface.
func (c *ttConn) Flush() error {
	return c.writer.Flush()
}

// Close makes ttConn satisfy the Conn interface.
func (c *ttConn) Close() error {
	return c.net.Close()
}

// Greeting makes ttConn satisfy the Conn interface.
func (c *ttConn) Greeting() tarantool.Greeting {
	return tarantool.Greeting{}
}

// ProtocolInfo makes ttConn satisfy the Conn interface.
func (c *ttConn) ProtocolInfo() tarantool.ProtocolInfo {
	return tarantool.ProtocolInfo{}
}
