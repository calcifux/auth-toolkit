package com.github.calcifux.authtoolkit;

import java.util.Map;

/**
 * Normalized identity extracted from a credential, BEFORE it is linked to a local
 * user. This is the output of a token verifier / introspector and the input to a
 * {@link PrincipalMapper} (just-in-time provisioning / account linking).
 *
 * <p>The link key is the pair {@code (issuer, externalId)} — never the email, which
 * is mutable and reusable across people. {@code email} and {@code displayName} are
 * display/profile data only, refreshed on each login.</p>
 *
 * @param issuer      the token issuer (OIDC {@code iss}); namespaces the externalId
 * @param externalId  the provider's stable, immutable subject (Entra {@code oid},
 *                     Firebase {@code uid}, generic {@code sub}, Sanctum token owner)
 * @param email       optional email (profile data, NOT an authorization key)
 * @param displayName optional human-readable name (profile data)
 * @param raw         the remaining claims/attributes, unmodified, for adapters that need more
 */
public record IdentityClaims(
        String issuer,
        String externalId,
        String email,
        String displayName,
        Map<String, Object> raw) {

    public IdentityClaims {
        if (externalId == null || externalId.isBlank()) {
            throw new IllegalArgumentException("IdentityClaims.externalId must not be blank");
        }
        raw = (raw == null) ? Map.of() : Map.copyOf(raw);
    }

    /** Stable, issuer-namespaced link key. Use THIS to find/create the local user. */
    public String linkKey() {
        return (issuer == null ? "" : issuer) + "|" + externalId;
    }
}
