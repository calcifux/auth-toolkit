# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2]

### Added

- **RS256 from local PEM files** — sign with a private key and verify with the public key, both
  read from the FILESYSTEM (absolute or working-dir-relative path, never the classpath), pure JDK
  (no BouncyCastle):
  - `RsaKeys` — loads PKCS#8 private (`BEGIN PRIVATE KEY`) and X.509 public (`BEGIN PUBLIC KEY`)
    PEM files; builds the signing/verification `RSAKey`; `publicJwksJson(...)` to expose a JWKS.
  - `JwtIssuer.rsaFromPem(issuer, kid, privateKeyPath, publicKeyPath)` — one-liner RS256 signer.
  - `JwtVerifier.rsaFromPem(issuer, audience, kid, publicKeyPath)` and
    `JwtVerifier.localRsa(settings, publicKey)` — verify your OWN tokens offline against a single
    local public key (fills the gap where verification previously required a JWKS URL or HMAC
    secret). `IdpProvider.selfLocalRsa(...)` is the matching preset.
- **`RsaKeyGenerator` + `KeyGenCli`** — generate an RSA keypair as PEM files (the kit's
  `passport:keys`); the private file is written `0600` on POSIX.

### Changed

- `JwtVerifierSettings` now permits NEITHER remote source (JWKS/HMAC) to support the local
  public-key mode; setting BOTH is still rejected. Backwards compatible — every prior preset is
  unchanged.

## [0.1.1]

### Added

- `AuthContext.populate(...)` and `AuthContext.clear()` are now public — **bring your own resolver**:
  an app that already resolves identity with its own filter can populate the toolkit context (so the
  `Auth` facade, `@CurrentUser` injection and the `@PreAuthorize` bridge work) without using
  `AuthResolverFilter` or re-resolving the credential.

## [0.1.0]

Initial release.

### Added

- **`auth-toolkit-core`** — framework-agnostic heart:
  - `AuthPrincipal` and `IdentityClaims` (canonical, IdP-agnostic).
  - `Ability` model + `AccessEvaluator` (RBAC now, ABAC-condition ready).
  - Resolver SPIs: `PrincipalMapper`, `TokenIntrospector`, `AbilityResolver`, `RolesLookup`,
    plus the ready-made `RoleBasedAbilityResolver`.
  - Nimbus-based `JwtVerifier` / `JwtIssuer` with presets for self-issued, Laravel Passport,
    Microsoft Entra ID, Firebase and generic OIDC.
- **`auth-toolkit-spring`** — Spring Boot starter:
  - Auto-configuration and `auth.toolkit.*` properties.
  - Per-request resolver-chain filter with header, bearer-JWT and opaque cookie-session adapters.
  - Static `Auth` facade (`Auth.can(...)`, `Auth.userId()`, ...).

[Unreleased]: https://github.com/calcifux/auth-toolkit/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/calcifux/auth-toolkit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/calcifux/auth-toolkit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/calcifux/auth-toolkit/releases/tag/v0.1.0
