# TLS certificates

KSwitch's admin UI is served over HTTPS at `https://localhost:5001/`.

## Two paths

### 1. Auto-generated self-signed (default)

```
make tls
```

Generates `./tls/cert.pem` + `./tls/key.pem` using your system `openssl`.
The private key is mode 600. **No OS trust-store changes** — your
browser will show a one-time warning ("Not Secure") that you accept once
per browser, then never again on the same machine. This avoids the
mkcert local-CA installation pattern, which many enterprise workstation
policies block.

### 2. Drop in your own CA-signed certs

Replace the generated files (or skip `make tls`) with your enterprise
PKI's certificate and private key:

```
cp /path/to/your/cert.pem ./tls/cert.pem
cp /path/to/your/key.pem  ./tls/key.pem
chmod 600 ./tls/key.pem
```

`make tls` is a no-op if `./tls/cert.pem` already exists, so re-running
`make up` will not overwrite your enterprise certs.

## Rotation

Self-signed certs from `make tls` expire after 825 days (the
Apple-recommended max). Re-run `make tls` after deleting `./tls/cert.pem`
+ `./tls/key.pem` to mint a fresh pair.
