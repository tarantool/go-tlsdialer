#!/usr/bin/env bash
# gen.sh — generate the CA + server cert pairs used by the tarantool-ee
# interop harness (start.sh / TestTarantoolEE_Ping).
#
# Each openssl step is best-effort: if one fails, the error is reported and
# the script moves on to the next step. That way a partial rerun (e.g. the
# server.csr already exists) still tries to produce the missing artefacts.
#
# Output:
#   ca.key, ca.crt                         — root CA
#   server.key, server.csr, server.crt     — RSA server pair (RSA-kex,
#                                            ECDHE-RSA, DHE-RSA suites)
#   server_ecdsa.key, server_ecdsa.csr,
#     server_ecdsa.crt                     — ECDSA P-256 server pair
#                                            (ECDHE-ECDSA-* suites)
#   server_gost.key, server_gost.csr,
#     server_gost.crt                      — GOST R 34.10-2012 256-bit server
#                                            pair (GOST2012-GOST8912-GOST8912
#                                            suites); generated only when
#                                            gost-engine is available
#   server_gost2001.key, server_gost2001.csr,
#     server_gost2001.crt                  — GOST R 34.10-2001 server pair
#                                            (GOST2001-GOST89-GOST89 suite);
#                                            generated only when gost-engine
#                                            is available
#   client.key, client.csr, client.crt     — RSA client pair for mTLS tests
#                                            (TestTarantoolEE_Ping_ClientAuth)
#   client_ecdsa.key, client_ecdsa.csr,
#     client_ecdsa.crt                     — ECDSA P-256 client pair for mTLS
#                                            tests
#   all .crt/.csr/.key files are gitignored
#
# Usage:
#   ./gen.sh

here=$(cd "$(dirname "$0")" && pwd)
cd "${here}" || exit 1

if ! command -v openssl >/dev/null; then
  echo "gen.sh: openssl not found on PATH" >&2
  exit 1
fi

step() {
  local desc=$1; shift
  echo "==> ${desc}"
  if ! "$@"; then
    echo "    ERROR: ${desc} failed (continuing)" >&2
  fi
}

step "generating CA key + cert" \
  openssl req -newkey rsa:2048 -nodes -keyout ca.key -x509 -days 3650 \
    -subj "/CN=Test CA" -out ca.crt

step "generating server key + CSR" \
  openssl req -newkey rsa:2048 -nodes -keyout server.key \
    -subj "/CN=localhost" -out server.csr

# Force SAN=localhost,127.0.0.1 so the cert validates whether the test
# dials by hostname or by IP.
san_ext=$(mktemp)
cat > "${san_ext}" <<'EOF'
subjectAltName = DNS:localhost, IP:127.0.0.1
EOF

step "signing server cert with CA" \
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 3650 \
    -extfile "${san_ext}"

# ECDSA server pair (P-256) — required for ECDHE-ECDSA-* suites.
step "generating ECDSA server key" \
  openssl ecparam -name prime256v1 -genkey -noout -out server_ecdsa.key

step "generating ECDSA server CSR" \
  openssl req -new -key server_ecdsa.key \
    -subj "/CN=localhost" -out server_ecdsa.csr

step "signing ECDSA server cert with CA" \
  openssl x509 -req -in server_ecdsa.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server_ecdsa.crt -days 3650 \
    -extfile "${san_ext}"

# RSA client pair — for TestTarantoolEE_Ping_ClientAuth (mTLS).
step "generating RSA client key + CSR" \
  openssl req -newkey rsa:2048 -nodes -keyout client.key \
    -subj "/CN=client" -out client.csr

step "signing RSA client cert with CA" \
  openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -days 3650

# ECDSA client pair (P-256) — key in PKCS#8 format so LoadPrivateKey accepts it
# ("EC PRIVATE KEY" from ecparam is not supported; genpkey outputs "PRIVATE KEY").
step "generating ECDSA client key (PKCS#8)" \
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out client_ecdsa.key

step "generating ECDSA client CSR" \
  openssl req -new -key client_ecdsa.key \
    -subj "/CN=client" -out client_ecdsa.csr

step "signing ECDSA client cert with CA" \
  openssl x509 -req -in client_ecdsa.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client_ecdsa.crt -days 3650

# GOST R 34.10-2012 (256-bit) + GOST R 34.10-2001 server pairs — required
# for GOST2012-GOST8912-GOST8912 / GOST2001-GOST89-GOST89 suites.
# These steps require gost-engine loaded via its OPENSSL_CONF. The config
# and the dylib ship with Homebrew's gost-engine@3.0.3 formula, which is
# built against OpenSSL 3 (engines-3 directory naming); a plain `openssl`
# on PATH may be an older (1.1.1) build that cannot load this engine.
#
# Binary resolution order:
#   1. ${GOST_OPENSSL} if set — explicit override (e.g. Linux CI).
#   2. /opt/homebrew/opt/openssl@3/bin/openssl if executable — macOS default.
#   3. `openssl` on PATH — last-resort fallback (works on Linux distros
#      where the system openssl matches the gost-engine build).
# If none resolves or the engine cnf is absent, GOST steps skip with a
# warning; the script still exits 0 and RSA/ECDSA pairs are unaffected.
gost_cnf=/opt/homebrew/etc/gost/gost-engine.cnf
gost_openssl=${GOST_OPENSSL:-/opt/homebrew/opt/openssl@3/bin/openssl}
if [[ ! -x "${gost_openssl}" ]]; then
  gost_openssl=$(command -v openssl || true)
fi
if [[ -f "${gost_cnf}" && -n "${gost_openssl}" && -x "${gost_openssl}" ]]; then
  step "generating GOST R 34.10-2012 server key" \
    env OPENSSL_CONF="${gost_cnf}" \
    "${gost_openssl}" genpkey -algorithm gost2012_256 -pkeyopt paramset:A \
      -out server_gost.key

  step "generating GOST server CSR" \
    env OPENSSL_CONF="${gost_cnf}" \
    "${gost_openssl}" req -new -key server_gost.key \
      -subj "/CN=localhost" -out server_gost.csr

  step "signing GOST server cert with CA" \
    env OPENSSL_CONF="${gost_cnf}" \
    "${gost_openssl}" x509 -req -in server_gost.csr -CA ca.crt -CAkey ca.key \
      -CAcreateserial -out server_gost.crt -days 3650 \
      -extfile "${san_ext}"

  # GOST R 34.10-2001 server pair — required for GOST2001-GOST89-GOST89.
  step "generating GOST R 34.10-2001 server key" \
    env OPENSSL_CONF="${gost_cnf}" \
    "${gost_openssl}" genpkey -algorithm gost2001 -pkeyopt paramset:A \
      -out server_gost2001.key

  step "generating GOST-2001 server CSR" \
    env OPENSSL_CONF="${gost_cnf}" \
    "${gost_openssl}" req -new -key server_gost2001.key \
      -subj "/CN=localhost" -out server_gost2001.csr

  step "signing GOST-2001 server cert with CA" \
    env OPENSSL_CONF="${gost_cnf}" \
    "${gost_openssl}" x509 -req -in server_gost2001.csr -CA ca.crt -CAkey ca.key \
      -CAcreateserial -out server_gost2001.crt -days 3650 \
      -extfile "${san_ext}"
else
  echo "gen.sh: WARNING: gost-engine config not found at ${gost_cnf}" \
    "or openssl@3 not installed at ${gost_openssl};" \
    "skipping GOST key/cert generation (server_gost.{key,csr,crt}," \
    "server_gost2001.{key,csr,crt})" >&2
fi

rm -f "${san_ext}"

echo
echo "generated files:"
for f in ca.key ca.crt \
         server.key server.csr server.crt \
         server_ecdsa.key server_ecdsa.csr server_ecdsa.crt \
         server_gost.key server_gost.csr server_gost.crt \
         server_gost2001.key server_gost2001.csr server_gost2001.crt \
         client.key client.csr client.crt \
         client_ecdsa.key client_ecdsa.csr client_ecdsa.crt; do
  if [[ -f "${f}" ]]; then
    printf "  OK   %s\n" "${f}"
  else
    printf "  MISS %s\n" "${f}"
  fi
done
