# keys/

Private key material NEVER lives in this repository. This directory exists
only as the conventional local mount point and is git-ignored for key files.

## Local development signing key

```sh
python -c "from taxstamps.crypto.eddsa import generate_pkcs8_pem; \
  open('keys/ed25519_pkcs8.pem','wb').write(generate_pkcs8_pem())"
chmod 600 keys/ed25519_pkcs8.pem
```

Point `TAXSTAMPS_SIGNING_KEY_PATH` at it. The service refuses to boot when
the file is group/world-readable, a symlink, unparseable, not Ed25519, or
contains placeholder markers (CHANGE_ME / DUMMY / PLACEHOLDER / EXAMPLE-KEY /
REPLACE_ME).

## Key directory (inbound envelope verification)

`keys/directory.json` (git-ignored) maps producer kids to base64url raw
32-byte Ed25519 public keys, per blueeconomy-contracts
`docs/envelope-signature.md`:

```json
{
  "blueeconomy-port-interoperability-0": "<b64u-pubkey>",
  "blueeconomy-tax-stamps-0": "<b64u-pubkey>"
}
```

To derive this service's public key entry after generating a key:

```sh
python - <<'EOF'
from taxstamps.crypto.eddsa import load_signing_key
import os
os.environ["TAXSTAMPS_ALLOW_PERMISSIVE_KEY_FILE"] = "1"
k = load_signing_key("keys/ed25519_pkcs8.pem", "blueeconomy-tax-stamps-0")
print(k.kid, k.public_key_b64u())
EOF
```

In production these files are mounted from the platform secret store by
GitOps; rotation increments the kid epoch (`blueeconomy-tax-stamps-1`, …).
