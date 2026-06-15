package com.github.calcifux.authtoolkit;

/**
 * Resolves a principal's authorization (roles + abilities) from LOCAL data.
 *
 * <p>This is the seam that keeps "identity from the token, authorization resolved
 * locally": adapters give you a {@link AuthPrincipal} (just a local user id), and the
 * application implements this SPI to look up that user's roles/abilities in its own
 * store — never trusting role/group claims from the IdP token.</p>
 *
 * <p>A ready-made RBAC implementation is {@link RoleBasedAbilityResolver}; for ABAC,
 * return abilities carrying {@link Ability#conditions()}.</p>
 */
@FunctionalInterface
public interface AbilityResolver {

    /** The roles + flattened abilities for this principal. Never {@code null}. */
    AuthorizationProfile resolve(AuthPrincipal principal);
}
