package com.github.calcifux.authtoolkit;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RoleBasedAbilityResolverTest {

    private final Map<String, List<Ability>> catalog = Map.of(
            "EDITOR", List.of(Ability.of("read", "article"), Ability.of("publish", "article")),
            "ADMIN", List.of(Ability.of("read", "article"), Ability.of("manage", "report")));

    @Test
    void flattensRolesToAbilitiesAndDedups() {
        RolesLookup roles = principal -> Set.of("EDITOR", "ADMIN");
        AbilityResolver resolver = new RoleBasedAbilityResolver(catalog, roles);

        AuthorizationProfile profile = resolver.resolve(AuthPrincipal.user(UUID.randomUUID()));

        assertThat(profile.roles()).containsExactlyInAnyOrder("EDITOR", "ADMIN");
        // read:article appears in both roles but is de-duplicated.
        assertThat(profile.abilities()).containsExactlyInAnyOrder(
                Ability.of("read", "article"),
                Ability.of("publish", "article"),
                Ability.of("manage", "report"));
    }

    @Test
    void emptyWhenNoRoles() {
        RolesLookup none = principal -> Set.of();
        AbilityResolver resolver = new RoleBasedAbilityResolver(catalog, none);

        AuthorizationProfile profile = resolver.resolve(AuthPrincipal.user(UUID.randomUUID()));

        assertThat(profile.roles()).isEmpty();
        assertThat(profile.abilities()).isEmpty();
    }
}
