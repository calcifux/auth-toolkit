package com.github.calcifux.authtoolkit;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Default RBAC {@link AbilityResolver}: it asks the application's {@link RolesLookup}
 * for the principal's roles, then flattens them to abilities through a static
 * role → abilities catalog. This is the "RBAC now" path; the catalog lives in code/config,
 * the per-user role assignment lives in the app's DB.
 *
 * <pre>{@code
 * var catalog = Map.of(
 *     "LEADER",  List.of(Ability.of("read", "workorder"), Ability.of("approve", "workorder")),
 *     "FINANCE", List.of(Ability.of("read", "budget"),    Ability.of("authorize", "budget")));
 * AbilityResolver resolver = new RoleBasedAbilityResolver(catalog, rolesLookup);
 * }</pre>
 */
public class RoleBasedAbilityResolver implements AbilityResolver {

    private final Map<String, List<Ability>> roleAbilities;
    private final RolesLookup rolesLookup;

    public RoleBasedAbilityResolver(Map<String, List<Ability>> roleAbilities, RolesLookup rolesLookup) {
        if (roleAbilities == null || rolesLookup == null) {
            throw new IllegalArgumentException("roleAbilities and rolesLookup are required");
        }
        this.roleAbilities = Map.copyOf(roleAbilities);
        this.rolesLookup = rolesLookup;
    }

    @Override
    public AuthorizationProfile resolve(AuthPrincipal principal) {
        Set<String> roles = rolesLookup.rolesFor(principal);
        if (roles == null || roles.isEmpty()) {
            return AuthorizationProfile.empty();
        }
        // De-dup abilities across roles, preserving order (a user with two roles that
        // both grant read:workorder should see it once).
        Set<Ability> flattened = new LinkedHashSet<>();
        for (String role : roles) {
            List<Ability> abilities = roleAbilities.get(role);
            if (abilities != null) {
                flattened.addAll(abilities);
            }
        }
        return new AuthorizationProfile(new LinkedHashSet<>(roles), new ArrayList<>(flattened));
    }
}
