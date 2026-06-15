# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/calcifux/auth-toolkit/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/calcifux/auth-toolkit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/calcifux/auth-toolkit/releases/tag/v0.1.0
