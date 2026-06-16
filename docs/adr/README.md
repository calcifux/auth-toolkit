# Architecture Decision Records

Architecture Decision Records for **auth-toolkit**. Format: lightweight MADR / Nygard — each
record states the context (the forces at play), the decision (grounded in the actual classes
and SPIs of this repo), and its consequences (positive and negative). Records are immutable
once accepted; a later decision supersedes rather than edits an earlier one.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-distribution-as-a-library.md) | Distribution as a library | Accepted |
| [0002](0002-identity-from-token-authorization-local.md) | Identity from the token, authorization resolved locally | Accepted |
| [0003](0003-one-resolver-chain-many-adapters.md) | One resolver chain, many adapters | Accepted |
| [0004](0004-rs256-from-local-pem-and-kid-rotation.md) | RS256 from local PEM files, with kid rotation | Accepted |
| [0005](0005-fail-closed.md) | Fail-closed semantics | Accepted |
| [0006](0006-spring-starter-and-static-facade.md) | Spring Boot starter and the static Auth facade | Accepted |
