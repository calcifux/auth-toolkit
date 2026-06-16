# 0004. RS256 from local PEM files, with kid rotation

- **Status:** Accepted
- **Date:** 2026-06-16

## Context
When a service is its own authorization server — issuing a session token or a
short-lived token for a downstream service — there is no external IdP and often no
JWKS endpoint to reach. Requiring a network round-trip to verify your own tokens is
needless coupling, and HMAC shared secrets give every verifier signing power (one
leaked secret forges tokens). Signing keys also need rotating, and rotating a key
must not log everyone out at once.

## Decision
Issue and verify your own RS256 tokens offline from local PEM key files, and
support graceful `kid` rotation via a multi-key local verifier.

- `JwtIssuer.rsaFromPem(issuer, keyId, privateKeyPath, publicKeyPath)` signs with
  the private key; `JwtVerifier.rsaFromPem(issuer, audience, keyId, publicKeyPath)`
  verifies with **only** the public key, so a second service can verify without ever
  holding signing power. No JWKS URL is needed — `IdpProvider.selfLocalRsa(...)`
  builds settings with neither remote source set, and the public key is handed to
  the verifier directly.
- Keys are read from the **filesystem** (absolute or working-dir-relative path),
  never the classpath — see `RsaKeys`. A private key in the jar can't be `chmod
  600`, can't be rotated without a rebuild, and ships in every artifact copy.
  Formats are the canonical pure-JDK ones (PKCS#8 private, X.509 public); the kit's
  `KeyGenCli` / `RsaKeyGenerator` produce them, as does `openssl` — no BouncyCastle.
- The signing algorithm is **pinned**: the verifier's key selector accepts only
  RS256 (or HS256 in secret mode), closing `alg:none` and RS256↔HS256 confusion
  regardless of the token header.
- Rotation rides on `kid`: `JwtIssuer.rsa` stamps the key's `kid` into every
  token header. `JwtVerifier.localRsa(settings, List<RSAKey>)` accepts several
  public keys, each with its own `kid`. During a rollover you keep the previous and
  the new public key in the set, so tokens minted under either `kid` verify until
  they expire; drop the old key once all its tokens have expired.
- The public key can be exposed as JWKS (`RsaKeys.publicJwksJson(...)`) at
  `GET /.well-known/jwks.json` for verifiers that prefer fetching it.

## Consequences
- Self-issued tokens verify with zero network dependency and zero shared signing
  power — verification needs only the public key.
- Key rotation is a no-downtime overlap: add the new key, start signing under its
  `kid`, retire the old key after the overlap window. No mass logout.
- Algorithm pinning removes a whole class of JWT downgrade attacks.
- Trade-off: operators must generate, deploy and protect the PEM files (and pass
  their paths via config / `.env`), and must manage the rotation overlap window
  themselves — the toolkit gives the mechanism, not a key-management service.
