package com.github.calcifux.authtoolkit.jwt;

/**
 * How to verify a JWT from one issuer and which claims carry identity. Build these
 * via {@link IdpProvider} presets (self / Passport / Entra / Firebase / generic OIDC)
 * or directly for a custom issuer.
 *
 * <p>Exactly one key source must be set: {@code jwksUri} (RS*, the norm for external
 * IdPs) OR {@code hmacSecret} (HS*, only viable when the same app issues and verifies).</p>
 *
 * @param issuer          expected {@code iss}; {@code null} skips the issuer check
 * @param jwksUri         JWKS endpoint for RS* verification ({@code null} if using a secret)
 * @param hmacSecret      shared secret for HS* verification ({@code null} if using JWKS)
 * @param audience        expected {@code aud}; {@code null} skips the audience check
 * @param externalIdClaim claim holding the stable subject (default {@code "sub"}; Entra {@code "oid"})
 * @param emailClaim      claim holding the email (default {@code "email"})
 * @param nameClaim       claim holding the display name (default {@code "name"})
 */
public record JwtVerifierSettings(
        String issuer,
        String jwksUri,
        String hmacSecret,
        String audience,
        String externalIdClaim,
        String emailClaim,
        String nameClaim) {

    public JwtVerifierSettings {
        boolean hasJwks = jwksUri != null && !jwksUri.isBlank();
        boolean hasSecret = hmacSecret != null && !hmacSecret.isBlank();
        if (hasJwks == hasSecret) {
            throw new IllegalArgumentException(
                    "Exactly one key source required: set jwksUri (RS*) OR hmacSecret (HS*)");
        }
        externalIdClaim = (externalIdClaim == null || externalIdClaim.isBlank()) ? "sub" : externalIdClaim;
        emailClaim = (emailClaim == null || emailClaim.isBlank()) ? "email" : emailClaim;
        nameClaim = (nameClaim == null || nameClaim.isBlank()) ? "name" : nameClaim;
    }

    /** {@code true} when verification uses a shared secret (HS*) rather than JWKS (RS*). */
    public boolean usesSharedSecret() {
        return hmacSecret != null && !hmacSecret.isBlank();
    }
}
