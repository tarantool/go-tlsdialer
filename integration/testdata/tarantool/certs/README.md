# TLS certificates for Tarantool-EE interop tests

This directory holds the TLS certificates used by the Tarantool-EE Docker
container. The certificates are NOT committed to version control.

Generate them with:

```sh
# CA
openssl req -newkey rsa:2048 -nodes -keyout ca.key -x509 -days 3650 \
  -subj "/CN=Test CA" -out ca.crt

# Server key + CSR
openssl req -newkey rsa:2048 -nodes -keyout server.key \
  -subj "/CN=localhost" -out server.csr

# Server cert signed by CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 3650
```

Required files (generated, gitignored):
- `ca.crt`     — CA certificate (also used by test clients)
- `ca.key`     — CA private key
- `server.crt` — Server certificate
- `server.key` — Server private key
