# auth-toolkit

Provider-agnostic authentication/authorization toolkit for Java services. One tiny
port resolves *who is calling* from any credential; pluggable adapters cover
self-issued JWT, inherited JWT (Laravel Passport), Microsoft Entra ID, Firebase and
opaque session/Sanctum tokens. An RBAC/ABAC ability model answers *what they may do*.

The guiding rule: **identity comes from the token; authorization is resolved locally.**
The token only proves who you are — roles and abilities are looked up in *your* data,
never trusted from IdP claims.

Write-side sibling conventions of [`remote-upload`](https://github.com/calcifux/remote-upload-java)
and [`remote-download`](https://github.com/calcifux/remote-download-java): a framework-
agnostic `-core` plus a Spring Boot `-spring` starter, published via JitPack.

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
  <version>0.1.0</version>
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

- **No credential** → anonymous (downstream guard decides).
- **Present but invalid** (bad JWT) → `401`.
- **Opaque session unknown/expired** → anonymous (normal expiry → login), not an error.

## Configure (pick a provider)

```yaml
auth:
  toolkit:
    skip-paths: [/actuator]
    session:                       # opaque HttpOnly cookie — the SPA front-channel
      enabled: true
      cookie-name: wo_session
    jwt:                           # bearer tokens — API / service-to-service
      enabled: false
      issuer:  https://login.microsoftonline.com/<tenant>/v2.0
      jwks-uri: https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys
      audience: <your-api-id>
      external-id-claim: oid       # Entra immutable subject
    header:                        # dev / trusted-proxy only
      enabled: false
```

## What your application provides

The adapters depend on small SPIs you implement against your own store:

- **`PrincipalMapper`** — verified `IdentityClaims` → local `AuthPrincipal`
  (just-in-time provisioning / linking by `(issuer, externalId)`).
- **`TokenIntrospector`** — opaque token (session cookie / Sanctum) → `IdentityClaims`
  via a DB lookup. *Required by the cookie-session adapter.*
- **`AbilityResolver`** — `AuthPrincipal` → `{roles, abilities}` from local data.
  Use the ready-made `RoleBasedAbilityResolver` (a role → abilities catalog + your
  `RolesLookup`) for RBAC; return abilities with `conditions` for ABAC later.

```java
@Bean
AbilityResolver abilityResolver(RolesLookup rolesLookup) {
    var catalog = Map.of(
        "LEADER",  List.of(Ability.of("read", "workorder"), Ability.of("approve", "workorder")),
        "FINANCE", List.of(Ability.of("read", "workorder"), Ability.of("authorize", "budget")));
    return new RoleBasedAbilityResolver(catalog, rolesLookup);
}
```

## Use it

```java
// In a controller / service:
if (!Auth.can("approve", "workorder")) throw new ForbiddenException();
UUID me = Auth.userId().orElseThrow();

// Build /me for the SPA (roles for labels, abilities for UI gating):
return new MeResponse(Auth.userId().orElseThrow(), Auth.roles(), Auth.abilities());
```

Client-side gating (hiding buttons on `abilities`) is UX only — the server check above
is the real enforcement.

## Issuing your own tokens

```java
var issuer = JwtIssuer.rsa("https://my-service", rsaKey);   // or JwtIssuer.hmac(...)
String accessToken = issuer.issue(userId.toString(), "downstream-api", Duration.ofMinutes(5), Map.of());
```

## Build

```bash
mvn verify          # build + tests
mvn -DskipTests install
```

Requires JDK 21. License: MIT.
