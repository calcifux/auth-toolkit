# 0002. Identity from the token, authorization resolved locally

- **Status:** Accepted
- **Date:** 2026-06-16

## Context
Identity providers (Entra ID, Passport, Firebase, generic OIDC) commonly emit
`roles` / `groups` claims inside their tokens. Trusting those claims for
authorization couples your access rules to the IdP's directory, leaks IdP role
taxonomy into your domain, and means a token minted elsewhere can assert what it
may do in your service. The IdP knows *who* the caller is; it does not own *what
that caller may do here*.

## Decision
The token proves identity only; authorization is always looked up locally.

- A verified credential is normalized to `IdentityClaims` — `(issuer, externalId,
  email, displayName, raw)`. The stable link key is `(issuer, externalId)` (see
  `IdentityClaims.linkKey()`), never the mutable `email`.
- The application's `PrincipalMapper` maps those claims to a local `AuthPrincipal`
  — a tiny record carrying only the **local** `userId` and an `operator` flag. It
  deliberately carries identity, not roles.
- Roles and abilities come from the application's `AbilityResolver`, which reads
  *local* data and returns an `AuthorizationProfile {roles, abilities}`. The
  ready-made `RoleBasedAbilityResolver` (a role → abilities catalog plus your
  `RolesLookup`) covers RBAC.
- Capabilities are modeled as `Ability(action, subject, conditions)` and checked by
  `AccessEvaluator`. Pure RBAC is the case where `conditions` is empty; ABAC is
  added later by populating `conditions` without changing the shape or any call
  site. The evaluator is fail-closed: with no resource/evaluator, a conditional
  ability does **not** grant.

## Consequences
- IdP role/group claims are never an authorization input — swapping or adding an
  IdP changes who can log in, not what anyone may do.
- Abilities are resolved per request from local data, so a permission change takes
  effect immediately and never goes stale inside a cached principal.
- The `(action, subject)` ability object is forward-compatible: RBAC today, ABAC
  later, same `Auth.can(...)` / `AccessEvaluator.can(...)` call sites.
- Trade-off: every application must implement `PrincipalMapper` and
  `AbilityResolver` against its own store — the toolkit cannot ship a default,
  because only the app owns its users and roles.
- Trade-off: resolving abilities on each request costs a lookup; applications that
  need it can cache inside their `AbilityResolver`.
