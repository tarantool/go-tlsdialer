#!/usr/bin/env bash
# Regenerates the private-key fixtures for keys_internal_test.go: one RSA and
# one EC key, written in every PEM form the OpenSSL CLI produces that the
# OpenSSL backend might be handed. The tests check each form decrypts to the
# plain key, or fails the way the table in the test expects.
#
# Written for OpenSSL 3; the PBES1 forms need its legacy provider.
set -euo pipefail
cd "$(dirname "$0")"

pass=testpassword
legacy=(-provider legacy -provider default)

openssl genrsa -traditional -out rsa.key 2048
openssl ecparam -name prime256v1 -genkey -noout -out ec.key

# Unencrypted.
openssl pkcs8 -topk8 -nocrypt -in rsa.key -out rsa.pkcs8.key
openssl pkcs8 -topk8 -nocrypt -in ec.key -out ec.pkcs8.key
openssl ecparam -name prime256v1 -out ec.params.key
cat ec.key >> ec.params.key
openssl req -x509 -new -key rsa.key -subj /CN=localhost -days 36500 -out rsa.crt
cat rsa.crt rsa.key > rsa.cert-then-key.pem
rm rsa.crt

# Legacy (Proc-Type / DEK-Info) encryption.
for c in aes128 aes192 aes256 des3; do
  openssl rsa -in rsa.key -"$c" -traditional -passout "pass:$pass" -out "rsa.legacy-$c.key"
done
for c in aes256 des3; do
  openssl ec -in ec.key -"$c" -passout "pass:$pass" -out "ec.legacy-$c.key"
done
openssl rsa "${legacy[@]}" -in rsa.key -des -traditional -passout "pass:$pass" \
  -out rsa.legacy-des.key
openssl rsa -in rsa.key -camellia256 -traditional -passout "pass:$pass" \
  -out rsa.legacy-camellia256.key

# PKCS#8 PBES2.
p8() { openssl pkcs8 -topk8 -in "$1" -passout "pass:$pass" -out "$2" "${@:3}"; }
p8 rsa.key rsa.p8-default.key
p8 ec.key ec.p8-default.key
p8 rsa.key rsa.p8-aes256-sha1.key -v2 aes-256-cbc -v2prf hmacWithSHA1
p8 rsa.key rsa.p8-aes256-sha224.key -v2 aes-256-cbc -v2prf hmacWithSHA224
p8 rsa.key rsa.p8-aes192-sha384.key -v2 aes-192-cbc -v2prf hmacWithSHA384
p8 rsa.key rsa.p8-aes128-sha512.key -v2 aes-128-cbc -v2prf hmacWithSHA512
p8 rsa.key rsa.p8-aes256-sha512-224.key -v2 aes-256-cbc -v2prf hmacWithSHA512-224
p8 rsa.key rsa.p8-aes256-sha512-256.key -v2 aes-256-cbc -v2prf hmacWithSHA512-256
p8 rsa.key rsa.p8-des3-sha256.key -v2 des-ede3-cbc
p8 rsa.key rsa.p8-des3-sha1.key -v2 des-ede3-cbc -v2prf hmacWithSHA1
p8 rsa.key rsa.p8-scrypt.key -v2 aes-256-cbc -scrypt
p8 rsa.key rsa.p8-camellia256.key -v2 camellia-256-cbc
p8 rsa.key rsa.p8-aria256.key -v2 aria-256-cbc

# PKCS#8 PBES1 and PKCS#12 PBE.
p8 rsa.key rsa.p8-pbe-sha1-3des.key -v1 PBE-SHA1-3DES
p8 rsa.key rsa.p8-pbe-sha1-2des.key -v1 PBE-SHA1-2DES
p8 rsa.key rsa.p8-pbe-md5-des.key -v1 PBE-MD5-DES "${legacy[@]}"
