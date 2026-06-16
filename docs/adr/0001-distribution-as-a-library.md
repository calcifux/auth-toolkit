# 0001. Distribution as a library

- **Status:** Accepted
- **Date:** 2026-06-16

## Context
auth-toolkit is a dependency that other Java services embed, not an application
that runs on its own. The naive Spring starter scaffold inherits
`spring-boot-starter-parent`, which drags in app-oriented build conventions
(repackaging into an executable jar, opinionated plugin config) that make no
sense for a library and would surface in every consumer's build. It also ships as
two modules (`auth-toolkit-core`, `auth-toolkit-spring`) that must release in
lockstep, and it is published via JitPack, whose build runs on an older Maven/JDK
and will not accept variable (`${revision}`) versions or recent plugin releases.

## Decision
Package and distribute the toolkit as a library, matching the convention shared
by the other calcifux navajas (the `remote-*` libraries):

- **No `<parent>`.** The parent `pom.xml` instead imports the
  `spring-boot-dependencies` BOM under `dependencyManagement` (`<scope>import</scope>`),
  so we get Boot's managed versions (spring-*, `jakarta.servlet-api`,
  `nimbus-jose-jwt`, junit/assertj/mockito/slf4j) without inheriting the
  app-oriented build of `spring-boot-starter-parent`.
- **Multi-module reactor with one `${revision}`.** A single source-of-truth
  `<revision>` (currently `0.1.3`) versions `auth-toolkit-parent` and both child
  modules; `flatten-maven-plugin` (`flattenMode=resolveCiFriendliesOnly`) resolves
  it to a literal at `process-resources`, so published POMs carry no variable.
- **Published via JitPack.** `jitpack.yml` forces `openjdk21` (the default JDK 8
  would fail on records / pattern matching) and builds `mvn clean install -DskipTests`
  for fast consumer fetches. groupId `com.github.calcifux`, JDK 21, MIT licensed
  (© Carlos Guillermo Reyes Ramiro).
- **JitPack-friendly plugin versions.** Build plugins are pinned to versions the
  older JitPack Maven accepts (`maven-compiler-plugin` 3.11.0,
  `maven-surefire-plugin` 3.1.2, `flatten-maven-plugin` 1.5.0). Deliberately **no
  SonarCloud / JaCoCo** — the toolkit stays basic and fast to build.
- **core + spring split.** `auth-toolkit-core` is pure Java (no Spring, no
  servlet); `auth-toolkit-spring` is the Boot starter. The framework-agnostic core
  is usable from any framework.

## Consequences
- Consumers get a clean transitive dependency with no executable-jar repackaging
  or app-oriented plugin leakage.
- One `${revision}` bump releases the whole reactor coherently; flattened POMs are
  portable and contain no unresolved variables.
- The core module is reusable outside Spring (e.g. a plain servlet or another
  framework), which is the reason for the split.
- Trade-off: pinning to JitPack-friendly tool versions means we lag the newest
  Maven plugins, and skipping coverage/quality gates on JitPack moves that
  enforcement to CI/local (`mvn verify`) rather than the published-artifact build.
- Trade-off: importing the Boot BOM (not inheriting it) means any plugin or
  property the starter-parent would have supplied must be declared explicitly here.
