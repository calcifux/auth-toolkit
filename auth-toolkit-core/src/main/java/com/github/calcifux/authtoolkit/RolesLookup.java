package com.github.calcifux.authtoolkit;

import java.util.Set;

/**
 * Application-supplied lookup of a principal's role codes from local data (typically
 * a {@code user_roles} table). Kept separate from ability mapping so the RBAC default
 * ({@link RoleBasedAbilityResolver}) can flatten roles → abilities while the app owns
 * only the cheap "which roles does this user have" query.
 */
@FunctionalInterface
public interface RolesLookup {

    /** The role codes assigned to the principal (e.g. {@code {"EDITOR"}}). Never {@code null}. */
    Set<String> rolesFor(AuthPrincipal principal);
}
