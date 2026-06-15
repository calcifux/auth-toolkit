# Examples

Illustrative, copy-pasteable usage of `auth-toolkit-spring` in a Spring Boot app.
These files are **reference only** — they are not part of the Maven build or the
published jars; adapt them to your own domain and data store.

- [`SecurityBeans.java`](SecurityBeans.java) — the beans your application supplies:
  `PrincipalMapper`, `TokenIntrospector`, `RolesLookup` and an `AbilityResolver`.
- [`ArticleController.java`](ArticleController.java) — endpoints: a `GET /api/me`
  identity endpoint and a guarded `POST /api/articles/{id}/publish`, using the static
  `Auth` facade.

Plus the `application.yml` that turns a provider on and enables the `@PreAuthorize`
support used by the controller:

```yaml
auth:
  toolkit:
    session:
      enabled: true
      cookie-name: app_session
    method-security:
      enabled: true          # for @PreAuthorize / @authz.can(...) — needs Spring Security
```

`@CurrentUser` injection works with just the starter (Spring MVC); the `@PreAuthorize`
lines additionally need Spring Security on the classpath.
