# 0005. Fail-closed semantics

- **Status:** Accepted
- **Date:** 2026-06-16

## Context
Auth code that swallows errors is dangerous: a verifier that returns "anonymous"
on a malformed token, or a key source that silently degrades when unreachable, can
turn a security failure into a quiet privilege grant or an unnoticed outage. Each
distinct outcome (no credential, bad credential, expired opaque session,
infrastructure failure) means something different and must be handled
distinctly — never collapsed into a silent downgrade.

## Decision
The toolkit standardizes four outcomes, and every adapter and the filter follow them:

- **No credential → anonymous.** A resolver that sees nothing for it returns
  `Optional.empty()`; the chain tries the next adapter and, if none resolves,
  `AuthContext` stays empty. A downstream guard (`@CurrentUser(required=true)`,
  `@PreAuthorize`, or an explicit `Auth.can(...)` check) decides whether anonymous
  is allowed — the resolver does not.
- **Present but invalid → 401.** A malformed/expired/wrong-issuer/wrong-audience
  JWT makes `JwtVerifier.verify` throw `TokenVerificationException`;
  `AuthResolverFilter` catches it and short-circuits to `401`
  (`application/problem+json`), never downgrading to anonymous.
- **Opaque session unknown/expired → anonymous.** `TokenIntrospector.introspect`
  returns `Optional.empty()` for an unknown/expired token and
  `CookieSessionAuthPrincipalResolver` treats that as anonymous. Session expiry is
  normal — the user is sent to login, not handed a `401` error.
- **Infrastructure failure → exception.** A JWKS/key-source that is unreachable
  throws `AuthToolkitException` (not `TokenVerificationException`), so it surfaces
  as a server error rather than being mistaken for a bad credential. The
  `AccessEvaluator` is likewise fail-closed: null/unknown abilities, or a
  conditional ability with no resource/evaluator, deny.

The `AuthPrincipalResolver` contract documents exactly these return semantics so a
custom adapter inherits the same discipline.

## Consequences
- The distinction between "not logged in", "bad token", "session ended" and
  "infra broke" is preserved end to end, so each gets the right response code and
  the right operator signal.
- No code path can silently downgrade an authentication failure into anonymous
  access.
- Trade-off: callers must explicitly enforce "must be authenticated" — anonymous is
  not auto-rejected, because some endpoints are public by design. The required-auth
  decision lives at the guard, not the resolver.
- Trade-off: an unreachable IdP key source fails requests (by design) rather than
  letting them through; availability of verification depends on availability of the
  key source (mitigated for self-issued tokens by ADR 0004's local keys).
