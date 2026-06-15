package com.github.calcifux.authtoolkit.jwt;

import com.github.calcifux.authtoolkit.AuthToolkitException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * Mints SELF-ISSUED JWTs — used when this service is its own authorization server (e.g.
 * to hand a short-lived access token to a second service or to SAP integrations). Prefer
 * {@link #rsa(String, RSAKey)} (asymmetric + a JWKS endpoint for verifiers) over
 * {@link #hmac(String, String)} (shared secret couples every verifier to one key).
 */
public final class JwtIssuer {

    private final String issuer;
    private final JWSAlgorithm algorithm;
    private final JWSSigner signer;
    private final String keyId;

    private JwtIssuer(String issuer, JWSAlgorithm algorithm, JWSSigner signer, String keyId) {
        this.issuer = issuer;
        this.algorithm = algorithm;
        this.signer = signer;
        this.keyId = keyId;
    }

    /** HS256 issuer from a shared secret (must be at least 256 bits / 32 chars). */
    public static JwtIssuer hmac(String issuer, String secret) {
        try {
            return new JwtIssuer(issuer, JWSAlgorithm.HS256, new MACSigner(secret.getBytes(StandardCharsets.UTF_8)), null);
        } catch (JOSEException e) {
            throw new AuthToolkitException("HMAC secret too short (need >= 256 bits / 32 chars)", e);
        }
    }

    /** RS256 issuer from an RSA key; the key's {@code kid} is carried in the header for rotation. */
    public static JwtIssuer rsa(String issuer, RSAKey rsaKey) {
        try {
            return new JwtIssuer(issuer, JWSAlgorithm.RS256, new RSASSASigner(rsaKey), rsaKey.getKeyID());
        } catch (JOSEException e) {
            throw new AuthToolkitException("Invalid RSA key for signing", e);
        }
    }

    /**
     * RS256 issuer that loads the keypair from PEM FILES on the filesystem (not the classpath) —
     * the jr-first one-liner: generate the keys once (see {@link RsaKeyGenerator} / {@code openssl}),
     * keep the private one secret, point config at the two paths. The {@code keyId} is stamped into
     * every token header so verifiers can rotate by {@code kid}.
     *
     * @param issuer         the {@code iss} to stamp on issued tokens
     * @param keyId          key id for rotation ({@code null} to omit {@code kid})
     * @param privateKeyPath filesystem path to the PKCS#8 private PEM (the SECRET, chmod 600)
     * @param publicKeyPath  filesystem path to the X.509 public PEM
     */
    public static JwtIssuer rsaFromPem(String issuer, String keyId, String privateKeyPath, String publicKeyPath) {
        return rsa(issuer, RsaKeys.signingKey(privateKeyPath, publicKeyPath, keyId));
    }

    /** Issue a token for {@code subject}, valid for {@code ttl}, with optional audience + extra claims. */
    public String issue(String subject, String audience, Duration ttl, Map<String, Object> extraClaims) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(issuer)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(ttl)));
        if (audience != null && !audience.isBlank()) {
            claims.audience(audience);
        }
        if (extraClaims != null) {
            extraClaims.forEach(claims::claim);
        }

        JWSHeader.Builder header = new JWSHeader.Builder(algorithm);
        if (keyId != null) {
            header.keyID(keyId);
        }

        SignedJWT jwt = new SignedJWT(header.build(), claims.build());
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new AuthToolkitException("JWT signing failed", e);
        }
        return jwt.serialize();
    }

    /** Convenience: a token with no audience and no extra claims. */
    public String issue(String subject, Duration ttl) {
        return issue(subject, null, ttl, Map.of());
    }
}
