# auth-toolkit

[![CI](https://github.com/calcifux/auth-toolkit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/calcifux/auth-toolkit/actions/workflows/ci.yml)
[![JitPack](https://jitpack.io/v/calcifux/auth-toolkit.svg)](https://jitpack.io/#calcifux/auth-toolkit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Java 21](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot 3.x](https://img.shields.io/badge/Spring%20Boot-3.x-6DB33F.svg)](https://spring.io/projects/spring-boot)

> **Provider-agnostic authentication & authorization for Java services.** One tiny port
> resolves *who is calling* from any credential; pluggable adapters cover self-issued JWT,
> inherited JWT (Laravel Passport), Microsoft Entra ID, Firebase and opaque session /
> Sanctum tokens. An RBAC/ABAC ability model answers *what they may do*.

```java
if (!Auth.can("publish", "article")) throw new ForbiddenException();
UUID me = Auth.userId().orElseThrow();
```

The guiding rule: **identity comes from the token; authorization is resolved locally.**
The token only proves *who you are* — roles and abilities are looked up in *your* data,
never trusted from IdP claims.

## Modules

| Module | What it is |
| --- | --- |
| `auth-toolkit-core` | Pure Java. The canonical `AuthPrincipal` + `IdentityClaims`, the `Ability` model + `AccessEvaluator`, the resolver SPIs, and a Nimbus-based `JwtVerifier`/`JwtIssuer`. No Spring, no servlet. |
| `auth-toolkit-spring` | Spring Boot starter: auto-configuration, `auth.toolkit.*` properties, the per-request resolver-chain filter, the adapters (header / bearer-JWT / cookie-session) and the static `Auth` facade. |

## Install (JitPack)

```xml
<repositories>
  <repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
  </repository>
</repositories>

<dependency>
  <groupId>com.github.calcifux.auth-toolkit</groupId>
  <artifactId>auth-toolkit-spring</artifactId>
  <version>v0.1.0</version>
</dependency>
```

## How it fits together

```
request ──> AuthResolverFilter ──> [ordered AuthPrincipalResolver chain]
                                     header(10) → bearer-JWT(20) → cookie-session(30)
                                          │ first that resolves wins
                                          ▼
                       IdentityClaims ──(PrincipalMapper)──> AuthPrincipal (local userId)
                                          │
                       AbilityResolver ──> AuthorizationProfile {roles, abilities}
                                          ▼
                                   AuthContext (per-thread)  ──read──>  Auth facade
```

- **No credential** → anonymous (a downstream guard decides).
- **Present but invalid** (bad JWT) → `401`.
- **Opaque session unknown/expired** → anonymous (normal expiry → login), not an error.

> **Bring your own resolver.** Already have an auth filter? Skip the toolkit's filter and call
> `AuthContext.populate(principal, profile)` from your own filter (clear it in a `finally`). The
> `Auth` facade, `@CurrentUser` injection and the `@PreAuthorize` bridge then work on top of your
> existing pipeline — no second credential resolution.

## Providers

Turn an adapter on with its `enabled` flag; run one (the typical case) or several in the
chain. Every example below is self-contained.

### Opaque cookie session (SPA front-channel / Sanctum)

The browser only ever holds an opaque HttpOnly cookie; the value is resolved against your
store via a `TokenIntrospector`.

```yaml
auth:
  toolkit:
    session:
      enabled: true
      cookie-name: app_session
```

### Bearer JWT — config-driven (Entra ID, Passport, generic OIDC)

Point the verifier at the issuer's JWKS endpoint; provider presets only differ in the
issuer, audience and subject claim.

```yaml
# Microsoft Entra ID
auth:
  toolkit:
    jwt:
      enabled: true
      issuer:  https://login.microsoftonline.com/<tenant>/v2.0
      jwks-uri: https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys
      audience: <your-api-id>
      external-id-claim: oid          # Entra's immutable subject
```

```yaml
# Laravel Passport (OAuth2 RS256)
auth:
  toolkit:
    jwt:
      enabled: true
      issuer:  https://passport.example.com
      jwks-uri: https://passport.example.com/oauth/jwks
      audience: my-api
```

```yaml
# Any standard OIDC provider
auth:
  toolkit:
    jwt:
      enabled: true
      issuer:  https://idp.example.com/
      jwks-uri: https://idp.example.com/.well-known/jwks.json
      audience: my-api
```

### Bearer JWT — code-driven presets (`IdpProvider`)

When you want to build the `JwtVerifier` yourself (e.g. multiple issuers, or Firebase),
expose your own bean — auto-config backs off via `@ConditionalOnMissingBean`.

```java
// Self-issued (HS256, shared secret) — issuer and verifier are the same app:
new JwtVerifier(IdpProvider.selfHmac("https://my-service", "my-api", secret));

// Self-issued (RS256 via your JWKS) — preferred (rotation, multi-verifier):
new JwtVerifier(IdpProvider.selfJwks("https://my-service", "my-api", "https://my-service/jwks.json"));

// Microsoft Entra ID:
new JwtVerifier(IdpProvider.entra("<tenant-id>", "<your-api-id>"));

// Laravel Passport:
new JwtVerifier(IdpProvider.passport("https://passport.example.com",
                                     "https://passport.example.com/oauth/jwks", "my-api"));

// Generic OIDC:
new JwtVerifier(IdpProvider.genericOidc("https://idp.example.com/",
                                        "https://idp.example.com/.well-known/jwks.json", "my-api"));

// Firebase — serves X.509 certs (not a JWKS), so pass a key source built over them:
JwtVerifierSettings firebase = IdpProvider.firebase("<project-id>");
new JwtVerifier(firebase, firebaseX509KeySource);   // your JWKSource over the securetoken certs
```

### Header (development / trusted proxy)

Trusts the caller — enable only behind a trusted gateway or in dev.

```yaml
auth:
  toolkit:
    header:
      enabled: true
      user: X-User-Id        # a local user UUID
      role: X-User-Role
```

## What your application provides

The adapters depend on small SPIs you implement against your own store:

- **`PrincipalMapper`** — verified `IdentityClaims` → local `AuthPrincipal`
  (just-in-time provisioning / linking by `(issuer, externalId)`).
- **`TokenIntrospector`** — opaque token (session cookie / Sanctum) → `IdentityClaims`
  via a DB lookup. *Required by the cookie-session adapter.*
- **`AbilityResolver`** — `AuthPrincipal` → `{roles, abilities}` from local data. Use the
  ready-made `RoleBasedAbilityResolver` (a role → abilities catalog + your `RolesLookup`)
  for RBAC; return abilities carrying `conditions` for ABAC later.

```java
@Bean
AbilityResolver abilityResolver(RolesLookup rolesLookup) {
    var catalog = Map.of(
        "EDITOR", List.of(Ability.of("read", "article"), Ability.of("publish", "article")),
        "ADMIN",  List.of(Ability.of("read", "article"), Ability.of("manage", "report")));
    return new RoleBasedAbilityResolver(catalog, rolesLookup);
}
```

## Use it in your endpoints

The resolver-chain filter has already populated the request context, so endpoints just
read it through the static `Auth` facade. A runnable illustration lives in
[`examples/`](examples) (`SecurityBeans.java` + `ArticleController.java`).

```java
@RestController
@RequestMapping("/api")
class ArticleController {

    // The identity payload the SPA hydrates: roles for labels, abilities for UI gating.
    record Me(UUID userId, Set<String> roles, List<Ability> abilities) {}

    @GetMapping("/me")
    Me me() {
        return new Me(Auth.userId().orElseThrow(), Auth.roles(), Auth.abilities());
    }

    @PostMapping("/articles/{id}/publish")
    void publish(@PathVariable UUID id) {
        if (!Auth.can("publish", "article")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        // ... publish. The server check above is the real enforcement point.
    }
}
```

Client-side gating (hiding buttons on `abilities`) is UX only — the server check is the
authority. They are two enforcement points, not one.

## Inject the current user (`@CurrentUser`)

Pull the identity straight into a handler parameter — idiomatic Spring MVC (a
`HandlerMethodArgumentResolver`, not arg-rewriting AOP). The injected value follows the
parameter type:

```java
@GetMapping("/me")
Me me(@CurrentUser AuthPrincipal principal) { ... }        // the principal (or null)

void create(@CurrentUser UUID userId) { ... }              // just the local user id
void audit(@CurrentUser AuthorizationProfile profile) {}   // roles + abilities
void maybe(@CurrentUser Optional<AuthPrincipal> who) {}    // explicit optionality
```

`@CurrentUser(required = true)` returns `401` on an anonymous request instead of injecting `null`.

## Declarative authorization (`@PreAuthorize`)

Opt in to the Spring Security bridge — it only auto-configures when Spring Security is on
the classpath:

```yaml
auth:
  toolkit:
    method-security:
      enabled: true
```

Then gate methods declaratively. The toolkit maps your resolved roles → `ROLE_<code>` and
abilities → authorities (`action:subject` by default), so the standard expressions work,
**driven by your own data**:

```java
@PreAuthorize("hasAuthority('publish:article')")
@PreAuthorize("hasAnyAuthority('publish:article', 'manage:report')")
@PreAuthorize("hasRole('EDITOR')")

// …or use the (action, subject) model directly (ABAC-extensible) via the `authz` bean:
@PreAuthorize("@authz.can('publish', 'article')")
```

Override the authority naming by exposing your own `AbilityAuthorityNaming` bean (e.g. to
emit flat permission codes).

## Issuing your own tokens

```java
var issuer = JwtIssuer.rsa("https://my-service", rsaKey);   // or JwtIssuer.hmac(...)
String accessToken = issuer.issue(userId.toString(), "downstream-api", Duration.ofMinutes(5), Map.of());
```

## Build

```bash
mvn verify              # build + tests
mvn -DskipTests install
```

Requires JDK 21.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). In short: open an issue to discuss non-trivial
changes, keep `mvn verify` green, and follow the existing style. Release notes live in
[CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) © Carlos Guillermo Reyes Ramiro
