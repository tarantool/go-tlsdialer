//go:build cgo && openssl_gost_engine

// gost_engine.go — loads the GOST engine into OpenSSL at
// package init time so GOST cipher names (e.g.
// "LEGACY-GOST2012-GOST8912-GOST8912") become available to
// SSL_CTX_set_cipher_list in the OpenSSL backend.
//
// Build constraint: cgo && openssl_gost_engine. The openssl_gost_engine tag is
// opt-in because the load has a process-wide side effect (it sets OpenSSL's
// default engine) and should not happen merely from importing the OpenSSL
// backend. In every other build GOST is handled by the pure-Go gostls backend
// without any engine.
//
// # Engine resolution (cross-OS)
//
// The engine is located at init time using this priority order:
//
//  1. ENGINE_by_id("gost") — zero-config when the engine is installed in
//     OpenSSL's ENGINESDIR or registered via openssl.cnf (typical on Linux
//     distros that ship libengine-gost-openssl / gost-engine).
//  2. The GOST_ENGINE_LIB environment variable — an explicit path to the engine
//     shared object. Highest-priority override for CI and non-standard installs.
//  3. A per-OS list of well-known candidate paths (Homebrew on macOS, the usual
//     engines-3 directories on Linux).
//
// If none succeed the engine is simply not loaded — GOSTEngineAvailable()
// returns false and the GOST-engine integration test skips. Non-GOST OpenSSL
// usage is unaffected.

package openssl

/*
#include <openssl/engine.h>
#include <stdlib.h>

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// X_load_gost_engine_by_id activates an already-registered "gost" engine
// (found in OpenSSL's ENGINESDIR or via openssl.cnf). Returns 0 on success.
static int X_load_gost_engine_by_id(void) {
	ENGINE *e = ENGINE_by_id("gost");
	if (!e) {
		return 1;
	}
	if (!ENGINE_init(e)) {
		ENGINE_free(e);
		return 2;
	}
	if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
		ENGINE_finish(e);
		ENGINE_free(e);
		return 3;
	}
	ENGINE_finish(e);
	ENGINE_free(e);
	return 0;
}

// X_load_gost_engine_dynamic loads the gost dynamic engine from the given
// shared-object path. Returns 0 on success, non-zero on failure.
//
// Reference-count pattern (per OpenSSL docs):
//   - ENGINE_by_id       — returns a structural reference, matched by ENGINE_free.
//   - ENGINE_init        — bumps the functional reference count.
//   - ENGINE_set_default — takes its own functional reference for the default slot.
//   - ENGINE_finish      — drops the functional reference obtained by ENGINE_init.
//   - ENGINE_free        — drops the structural reference.
// The default-slot functional reference keeps the engine alive for the process.
static int X_load_gost_engine_dynamic(const char *dylib_path) {
	ENGINE_load_dynamic();
	ENGINE *e = ENGINE_by_id("dynamic");
	if (!e) {
		return 1;
	}
	if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", dylib_path, 0)) {
		ENGINE_free(e);
		return 2;
	}
	if (!ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
		ENGINE_free(e);
		return 3;
	}
	if (!ENGINE_init(e)) {
		ENGINE_free(e);
		return 4;
	}
	if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
		ENGINE_finish(e);
		ENGINE_free(e);
		return 5;
	}
	ENGINE_finish(e);
	ENGINE_free(e);
	return 0;
}
*/
import "C"

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"
)

// gostEngineErr records the outcome of the load attempt at package init.
// nil means the engine is active and GOST cipher names are usable.
var gostEngineErr = loadGOSTEngine()

// GOSTEngineAvailable reports whether the GOST OpenSSL engine was loaded and set
// as default, i.e. whether GOST cipher suites can be negotiated through the
// OpenSSL backend. It is only defined in builds with -tags openssl_gost_engine.
func GOSTEngineAvailable() bool { return gostEngineErr == nil }

// GOSTEngineError returns the reason the engine failed to load, or nil.
func GOSTEngineError() error { return gostEngineErr }

func loadGOSTEngine() error {
	// 1. Already registered (ENGINESDIR / openssl.cnf) — no path needed.
	if C.X_load_gost_engine_by_id() == 0 {
		return nil
	}

	// 2 & 3. Dynamic load from an explicit path or per-OS candidates.
	candidates := gostEngineCandidates()
	var tried []string
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		tried = append(tried, p)
		cs := C.CString(p)
		rc := C.X_load_gost_engine_dynamic(cs)
		C.free(unsafe.Pointer(cs))
		if rc == 0 {
			return nil
		}
	}

	if len(tried) == 0 {
		return fmt.Errorf("gost engine: not registered with OpenSSL and no engine library found; "+
			"set GOST_ENGINE_LIB to its path (searched: %v)", candidates)
	}
	return fmt.Errorf("gost engine: found but failed to load from %v", tried)
}

// gostEngineCandidates returns the engine shared-object paths to probe, in
// priority order. GOST_ENGINE_LIB, when set, wins outright.
func gostEngineCandidates() []string {
	if v := os.Getenv("GOST_ENGINE_LIB"); v != "" {
		return []string{v}
	}
	switch runtime.GOOS {
	case "darwin":
		return []string{
			// Homebrew (Apple Silicon), keg-only formula:
			"/opt/homebrew/opt/gost-engine@3.0.3/libexec/engines-3/gost.dylib",
			"/opt/homebrew/lib/engines-3/gost.dylib",
			// Homebrew (Intel):
			"/usr/local/opt/gost-engine@3.0.3/libexec/engines-3/gost.dylib",
			"/usr/local/lib/engines-3/gost.dylib",
		}
	case "linux":
		return []string{
			"/usr/lib/x86_64-linux-gnu/engines-3/gost.so", // Debian/Ubuntu
			"/usr/lib64/engines-3/gost.so",                // Fedora/RHEL
			"/usr/lib/engines-3/gost.so",
			"/usr/local/lib/engines-3/gost.so",
			"/usr/local/lib64/engines-3/gost.so",
		}
	default:
		return nil
	}
}
