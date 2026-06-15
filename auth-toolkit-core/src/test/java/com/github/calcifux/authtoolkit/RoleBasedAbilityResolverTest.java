package com.github.calcifux.authtoolkit;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RoleBasedAbilityResolverTest {

    private final Map<String, List<Ability>> catalog = Map.of(
            "LEADER", List.of(Ability.of("read", "workorder"), Ability.of("approve", "workorder")),
            "FINANCE", List.of(Ability.of("read", "workorder"), Ability.of("authorize", "budget")));

    @Test
    void flattensRolesToAbilitiesAndDedups() {
        RolesLookup roles = principal -> Set.of("LEADER", "FINANCE");
        AbilityResolver resolver = new RoleBasedAbilityResolver(catalog, roles);

        AuthorizationProfile profile = resolver.resolve(AuthPrincipal.user(UUID.randomUUID()));

        assertThat(profile.roles()).containsExactlyInAnyOrder("LEADER", "FINANCE");
        // read:workorder appears in both roles but is de-duplicated.
        assertThat(profile.abilities()).containsExactlyInAnyOrder(
                Ability.of("read", "workorder"),
                Ability.of("approve", "workorder"),
                Ability.of("authorize", "budget"));
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
