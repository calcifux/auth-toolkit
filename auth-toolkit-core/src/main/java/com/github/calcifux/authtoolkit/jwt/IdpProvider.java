package com.github.calcifux.authtoolkit.jwt;

/**
 * Presets that build {@link JwtVerifierSettings} for the common identity providers,
 * so the caller only supplies the few values that actually differ. Identity is still
 * taken from the token only; authorization stays local.
 *
 * <ul>
 *   <li><b>self / Passport</b> — your own or a Laravel Passport issuer (RS* via JWKS, or HS* secret).</li>
 *   <li><b>Entra ID</b> — issuer/JWKS derived from the tenant; subject claim is {@code oid}
 *       (immutable), audience MUST be your API's id (confused-deputy guard).</li>
 *   <li><b>Firebase</b> — issuer {@code https://securetoken.google.com/<projectId>}, audience
 *       == projectId, subject {@code user_id}. NOTE: Firebase serves X.509 certs, not a
 *       standard JWKS, so wire {@link JwtVerifier}'s advanced constructor with a key source
 *       for those certs (the {@code jwksUri} here is a placeholder for that source).</li>
 * </ul>
 */
public final class IdpProvider {

    private IdpProvider() {
        // Utility class.
    }

    /** Self-issued tokens verified with a shared secret (HS256). Issuer+verifier are the same app. */
    public static JwtVerifierSettings selfHmac(String issuer, String audience, String secret) {
        return new JwtVerifierSettings(issuer, null, secret, audience, "sub", "email", "name");
    }

    /** Self-issued tokens verified via your own JWKS endpoint (RS256) — preferred over HS for rotation. */
    public static JwtVerifierSettings selfJwks(String issuer, String audience, String jwksUri) {
        return new JwtVerifierSettings(issuer, jwksUri, null, audience, "sub", "email", "name");
    }

    /** Laravel Passport access tokens (OAuth2 RS256) — point at Passport's JWKS endpoint. */
    public static JwtVerifierSettings passport(String issuer, String jwksUri, String audience) {
        return new JwtVerifierSettings(issuer, jwksUri, null, audience, "sub", "email", "name");
    }

    /**
     * Microsoft Entra ID (v2.0 tokens). {@code audience} MUST be your API's App ID URI / client id.
     *
     * @param tenantId the directory (tenant) id
     * @param audience your API's expected {@code aud}
     */
    public static JwtVerifierSettings entra(String tenantId, String audience) {
        String issuer = "https://login.microsoftonline.com/" + tenantId + "/v2.0";
        String jwksUri = "https://login.microsoftonline.com/" + tenantId + "/discovery/v2.0/keys";
        // oid is the immutable per-tenant user id; preferred_username/email are mutable.
        return new JwtVerifierSettings(issuer, jwksUri, null, audience, "oid", "preferred_username", "name");
    }

    /**
     * Firebase Auth ID tokens. The key source is Google's X.509 cert endpoint (NOT a JWKS),
     * so build the {@link JwtVerifier} with its advanced (JWKSource) constructor for these.
     *
     * @param projectId the Firebase project id (also the expected audience)
     */
    public static JwtVerifierSettings firebase(String projectId) {
        String issuer = "https://securetoken.google.com/" + projectId;
        String x509CertsUrl = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
        return new JwtVerifierSettings(issuer, x509CertsUrl, null, projectId, "user_id", "email", "name");
    }

    /** Any standard OIDC provider that publishes a JWKS endpoint. */
    public static JwtVerifierSettings genericOidc(String issuer, String jwksUri, String audience) {
        return new JwtVerifierSettings(issuer, jwksUri, null, audience, "sub", "email", "name");
    }
}
