package com.github.calcifux.authtoolkit;

import java.util.UUID;

/**
 * The canonical, IdP-agnostic principal: who is making the request, resolved to a
 * <b>local</b> user id. Every adapter (JWT, opaque/session, header) normalizes its
 * native token shape down to this tiny record.
 *
 * <p>Kept deliberately small: it carries IDENTITY, not authorization. Roles and
 * abilities are resolved separately (see {@link AbilityResolver}) and just-in-time,
 * so they never go stale inside a cached principal.</p>
 *
 * @param userId   the LOCAL user id (not the external IdP subject); see {@link PrincipalMapper}
 * @param operator {@code true} for an internal operator (direct/admin access, bypasses scoping)
 */
public record AuthPrincipal(UUID userId, boolean operator) {

    public AuthPrincipal {
        if (userId == null) {
            throw new IllegalArgumentException("AuthPrincipal.userId must not be null");
        }
    }

    /** Convenience for the common case of a non-operator (scoped) user. */
    public static AuthPrincipal user(UUID userId) {
        return new AuthPrincipal(userId, false);
    }

    /** Convenience for an internal operator principal. */
    public static AuthPrincipal operator(UUID userId) {
        return new AuthPrincipal(userId, true);
    }
}
