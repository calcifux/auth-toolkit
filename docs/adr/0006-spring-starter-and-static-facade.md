# 0006. Spring Boot starter and the static Auth facade

- **Status:** Accepted
- **Date:** 2026-06-16

## Context
The framework-agnostic core (ADR 0001) needs almost no wiring to be useful in a
Spring Boot service, and the day-to-day developer experience should be a one-liner
authorization check in a controller — not boilerplate to fetch the current user out
of a thread-local on every call. At the same time, applications must be able to
override any piece (their own resolver, their own `JwtVerifier`, their own authority
naming), and optional integrations (Spring MVC, Spring Security) must not be forced
on apps that don't use them.

## Decision
Ship `auth-toolkit-spring` as a Spring Boot starter that auto-configures the
read/write plumbing, exposing a static facade for the common check. Three
auto-configurations are registered in `AutoConfiguration.imports`:

- `AuthToolkitAutoConfiguration` — binds `auth.toolkit.*`
  (`AuthToolkitProperties`), registers `AuthResolverFilter` and the adapters whose
  `enabled` flag is set. Every bean is `@ConditionalOnMissingBean` so the app can
  override any of them; adapters needing app data are also `@ConditionalOnBean`
  (e.g. the cookie-session adapter requires `TokenIntrospector` + `PrincipalMapper`).
- `AuthToolkitWebMvcAutoConfiguration` — `@ConditionalOnClass(WebMvcConfigurer)`;
  registers `CurrentUserArgumentResolver` so `@CurrentUser` injects the current
  identity straight into a handler parameter (typed `AuthPrincipal`, `UUID`,
  `AuthorizationProfile`, or `Optional<AuthPrincipal>`; `required=true` yields `401`
  on anonymous). It is a `HandlerMethodArgumentResolver`, idiomatic Spring MVC, not
  arg-rewriting AOP.
- `AuthToolkitMethodSecurityAutoConfiguration` — opt-in
  (`auth.toolkit.method-security.enabled=true`) and
  `@ConditionalOnClass(EnableMethodSecurity)`, so it only activates when Spring
  Security is on the classpath. It enables `@PreAuthorize` and wires the
  `SecurityContextBridgeFilter` (roles → `ROLE_<code>`, abilities → authorities via
  the overridable `AbilityAuthorityNaming`, default `action:subject`) plus the
  `authz` bean for `@PreAuthorize("@authz.can('publish','article')")`.

The static `Auth` facade (`Auth.can(action, subject)`, `Auth.userId()`,
`Auth.roles()`, `Auth.abilities()`, `Auth.isOperator()`) reads the per-thread
`AuthContext` the filter populated, so an authorization check is a pure
thread-local read with no injected dependency. The Spring Security
dependencies and `spring-webmvc` are declared `optional` in the POM so the
facade-only mode stays lightweight.

## Consequences
- Drop the starter in, set one property to pick a provider, and controllers do
  `if (!Auth.can("publish", "article")) …` or `@PreAuthorize` / `@CurrentUser` —
  minimal ceremony.
- The `@PreAuthorize` bridge lets standard Spring Security expressions work, but
  **driven by the app's own resolved roles/abilities** rather than IdP claims (ADR
  0002), reusing existing Spring Security idiom where teams already know it.
- Everything is `@ConditionalOnMissingBean` / class-gated, so apps override pieces
  freely and unused integrations cost nothing.
- Trade-off: the static `Auth` facade is convenient but a global access point —
  it reads a thread-local, so it only works on the request thread (work dispatched
  to other threads must capture the values first), and it is harder to mock than an
  injected dependency. `AuthContext` is always cleared in `finally` to avoid leaking
  across pooled servlet threads.
