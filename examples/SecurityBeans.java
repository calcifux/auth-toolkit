// ILLUSTRATIVE — not part of the build. Shows the application-supplied beans the toolkit
// adapters depend on. Replace the in-memory/demo bodies with your own data store.
package com.example.demo;

import com.github.calcifux.authtoolkit.Ability;
import com.github.calcifux.authtoolkit.AbilityResolver;
import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.IdentityClaims;
import com.github.calcifux.authtoolkit.PrincipalMapper;
import com.github.calcifux.authtoolkit.RoleBasedAbilityResolver;
import com.github.calcifux.authtoolkit.RolesLookup;
import com.github.calcifux.authtoolkit.TokenIntrospector;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Wires the local-data SPIs. Identity comes from the token (resolved by the adapter);
 * authorization is resolved here, against YOUR store — never trusted from IdP claims.
 */
@Configuration
class SecurityBeans {

    /**
     * Opaque session cookie → identity. In a real app this hashes the token and looks it
     * up in your {@code sessions} table (or, for Laravel Sanctum, {@code personal_access_tokens}).
     */
    @Bean
    TokenIntrospector tokenIntrospector(/* SessionRepository sessions */) {
        return token -> {
            // var session = sessions.findActiveByTokenHash(sha256(token));
            // return session.map(s -> new IdentityClaims("local", s.userId().toString(), null, null, Map.of()));
            return Optional.empty();
        };
    }

    /**
     * Verified identity → local user. Find by {@code (issuer, externalId)} and provision on
     * first login (least privilege), then return the LOCAL user id.
     */
    @Bean
    PrincipalMapper principalMapper(/* UserRepository users */) {
        return (IdentityClaims claims) -> {
            // var user = users.findByExternalId(claims.linkKey())
            //         .orElseGet(() -> users.provision(claims));   // JIT, no roles by default
            // return AuthPrincipal.user(user.id());
            throw new UnsupportedOperationException("wire to your user store");
        };
    }

    /** Which roles a user has (your {@code user_roles} table). */
    @Bean
    RolesLookup rolesLookup(/* UserRoleRepository userRoles */) {
        return (AuthPrincipal principal) -> /* userRoles.codesFor(principal.userId()) */ java.util.Set.of("EDITOR");
    }

    /** Role → abilities catalog (RBAC). Add {@code conditions} to an ability later for ABAC. */
    @Bean
    AbilityResolver abilityResolver(RolesLookup rolesLookup) {
        Map<String, List<Ability>> catalog = Map.of(
                "EDITOR", List.of(Ability.of("read", "article"), Ability.of("publish", "article")),
                "ADMIN", List.of(Ability.of("read", "article"), Ability.of("manage", "report")));
        return new RoleBasedAbilityResolver(catalog, rolesLookup);
    }
}
