# 0003. One resolver chain, many adapters

- **Status:** Accepted
- **Date:** 2026-06-16

## Context
A service may accept more than one kind of credential: an opaque session cookie
from an SPA, a bearer JWT from another service, a trusted header behind a gateway
in dev. The tempting shape is one filter with `if (hasCookie) … else if (hasBearer)
… else if (hasHeader) …`. That branch grows with every provider, mixes verification
concerns, and is hard to reorder or test. Some applications also already have their
own auth filter and only want the toolkit's read-side conveniences on top.

## Decision
Resolution goes through a single per-request port with config-selected, ordered
adapters; the first that resolves wins.

- The port is `AuthPrincipalResolver` (one method:
  `Optional<AuthPrincipal> resolve(HttpServletRequest)`, plus an `order()`). It is
  the Passport-strategy / Spring `AuthenticationProvider` shape distilled to one
  method.
- `AuthResolverFilter` collects every `AuthPrincipalResolver` bean, sorts by
  `order()`, and runs them in turn; the first non-empty result wins, then the
  `AbilityResolver` is run once and the result cached in `AuthContext` for the
  request.
- The shipped adapters carry fixed orders so the chain is deterministic:
  `HeaderAuthPrincipalResolver` (10) → `BearerJwtAuthPrincipalResolver` (20) →
  `CookieSessionAuthPrincipalResolver` (30). Each is registered by auto-config
  only when its `auth.toolkit.<adapter>.enabled=true` flag is set.
- **A new provider is a new resolver bean**, never another branch inside an
  existing one. Auto-config beans are `@ConditionalOnMissingBean`, so you can
  replace or add adapters.
- **Bring your own resolver.** An application with its own filter can skip
  `AuthResolverFilter` entirely and call
  `AuthContext.populate(principal, profile)` (paired with `AuthContext.clear()` in
  a `finally`). The `Auth` facade, `@CurrentUser` injection and the `@PreAuthorize`
  bridge then work on top of the existing pipeline with no second credential
  resolution.

## Consequences
- Provider selection is pure configuration; running one provider (the appliance
  norm) or stacking several is the same mechanism.
- Each adapter is small, single-purpose and independently testable; reordering is
  just an `order()` change.
- The port is the one stable extension seam — adding Firebase, mTLS, etc. never
  edits existing code.
- The bring-your-own-resolver escape hatch means the toolkit's read side is usable
  even where its filter is not adopted.
- Trade-off: with several adapters enabled, "which one resolved this request" is
  decided by order; the convention (header → bearer → cookie) must be understood,
  and a misordered custom resolver can shadow another.
