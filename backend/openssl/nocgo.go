//go:build !cgo

package openssl

// This package links the system OpenSSL library through
// github.com/tarantool/go-openssl and therefore requires cgo. Building it with
// CGO_ENABLED=0 cannot work, so fail loudly here with a readable message
// instead of letting the build fall through to a confusing "undefined: New".
//
// The identifier name is the message: the compiler reports
//
//	undefined: This_package_requires_CGO_ENABLED_1
const builtWithCgo = This_package_requires_CGO_ENABLED_1
