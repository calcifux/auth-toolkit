// ILLUSTRATIVE — not part of the build. Endpoint usage: @CurrentUser injection (the dev
// "magic") and declarative @PreAuthorize gating, both driven by the toolkit's resolved identity.
// Requires `auth.toolkit.method-security.enabled=true` (and Spring Security on the classpath)
// for the @PreAuthorize annotations below.
package com.example.demo;

import com.github.calcifux.authtoolkit.Ability;
import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.spring.Auth;
import com.github.calcifux.authtoolkit.spring.web.CurrentUser;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Set;
import java.util.UUID;

@RestController
@RequestMapping("/api")
class ArticleController {

    /** The identity payload the SPA hydrates: roles for labels, abilities for UI gating. */
    record Me(UUID userId, Set<String> roles, List<Ability> abilities) {}

    /**
     * GET /api/me — the current user is INJECTED (@CurrentUser). The resolver-chain filter
     * already populated the request from the session cookie / bearer token.
     */
    @GetMapping("/me")
    Me me(@CurrentUser(required = true) AuthPrincipal principal) {
        return new Me(principal.userId(), Auth.roles(), Auth.abilities());
    }

    /**
     * Declarative gating via ability-as-authority: requires "publish:article".
     * (Or write it against roles: hasRole('EDITOR').)
     */
    @PreAuthorize("hasAuthority('publish:article')")
    @PostMapping("/articles/{id}/publish")
    void publish(@PathVariable UUID id) {
        // reached only if authorized.
    }

    /**
     * Declarative gating via our (action, subject) model — no authority-string flattening,
     * and ABAC-extensible later.
     */
    @PreAuthorize("@authz.can('read', 'article')")
    @GetMapping("/articles/{id}")
    String read(@PathVariable UUID id, @CurrentUser UUID userId) {
        return "article " + id + " read by " + userId;
    }

    /** Imperative check (no method security needed) — equivalent, your call. */
    @PostMapping("/articles/{id}/archive")
    void archive(@PathVariable UUID id) {
        if (!Auth.can("archive", "article")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
    }
}
