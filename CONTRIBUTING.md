# Contributing to auth-toolkit

Thanks for your interest in improving auth-toolkit! Contributions of all sizes are
welcome — bug reports, docs, tests, new provider adapters.

## Ground rules

- Be respectful — see the [Code of Conduct](CODE_OF_CONDUCT.md).
- Open an **issue** to discuss non-trivial changes before sending a PR.
- Keep the build green: `mvn verify` must pass (it runs the unit tests).
- Match the existing style: full words over abbreviations, focused classes, Javadoc on
  public types, and comments that explain the *why*.

## Development setup

```bash
git clone https://github.com/calcifux/auth-toolkit.git
cd auth-toolkit
mvn verify          # build + run tests (JDK 21 required)
```

The project is a two-module Maven reactor:

- `auth-toolkit-core` — framework-agnostic model, ability evaluator, SPIs, JWT verify/issue.
  Keep it free of Spring and servlet dependencies.
- `auth-toolkit-spring` — Spring Boot starter (auto-config, adapters, filter, facade).

## Design rules to preserve

- **Identity from the token, authorization resolved locally.** Adapters must only yield a
  stable subject; never trust IdP role/group claims for authorization.
- **One port, many adapters.** New providers are new `AuthPrincipalResolver` implementations
  selected by config — never `if/else` branching inside an existing resolver.
- **Fail-closed.** Unknown/absent input denies; a present-but-invalid token is a `401`, an
  infrastructure failure is an exception — never a silent downgrade to anonymous.

## Adding a provider adapter

1. Add an `AuthPrincipalResolver` (in `auth-toolkit-spring`) or, for pure verification logic,
   extend the `auth-toolkit-core` JWT/introspection support.
2. Register it in `AuthToolkitAutoConfiguration` behind its own `@ConditionalOnProperty`
   and `@ConditionalOnMissingBean`.
3. Add config to `AuthToolkitProperties` under `auth.toolkit.*`.
4. Cover it with a test.

## Pull requests

- Branch from `main`, keep PRs focused, and describe the change and motivation.
- Add/adjust tests for behavior changes.
- The CI workflow runs `mvn verify` on every PR.

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
