package com.github.calcifux.authtoolkit;

/**
 * Maps verified {@link IdentityClaims} (from any IdP) to a LOCAL {@link AuthPrincipal}.
 * This is where just-in-time provisioning and account linking happen: find the local
 * user by {@code (issuer, externalId)} (see {@link IdentityClaims#linkKey()}), create
 * it on first login if absent (least privilege, no roles), and return its local id.
 *
 * <p>Implemented by the application because only it owns the user store. Adapters call
 * this once at login/verification so the rest of the app depends only on the local id.</p>
 */
@FunctionalInterface
public interface PrincipalMapper {

    /**
     * Resolve (or provision) the local principal for these claims.
     *
     * @throws AuthToolkitException if the identity cannot be mapped (e.g. account disabled)
     */
    AuthPrincipal map(IdentityClaims claims);
}
