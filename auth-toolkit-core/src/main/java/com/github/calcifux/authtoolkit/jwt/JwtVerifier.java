package com.github.calcifux.authtoolkit.jwt;

import com.github.calcifux.authtoolkit.AuthToolkitException;
import com.github.calcifux.authtoolkit.IdentityClaims;
import com.github.calcifux.authtoolkit.TokenVerificationException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Verifies a JWT and normalizes it to {@link IdentityClaims}. Built on Nimbus so JWKS
 * fetching, {@code kid} selection and key rotation are handled for you.
 *
 * <p>Covers self-issued, Laravel Passport, Entra ID and any standard OIDC issuer via
 * {@code jwksUri} (RS*) or {@code hmacSecret} (HS*). For Firebase (X.509 certs, not a
 * standard JWKS), use the advanced constructor and pass a {@link JWKSource} built over
 * those certs.</p>
 *
 * <p>Failure semantics: a present-but-invalid token throws {@link TokenVerificationException}
 * (a 401); a key-source/infrastructure problem throws {@link AuthToolkitException} (never
 * silently downgraded to anonymous).</p>
 */
public class JwtVerifier {

    private final JwtVerifierSettings settings;
    private final ConfigurableJWTProcessor<SecurityContext> processor;

    /** Standard construction: derives the key source from {@code settings} (JWKS or secret). */
    public JwtVerifier(JwtVerifierSettings settings) {
        this(settings, defaultKeySource(settings));
    }

    /** Advanced construction: supply your own key source (e.g. Firebase X.509 certs). */
    public JwtVerifier(JwtVerifierSettings settings, JWKSource<SecurityContext> keySource) {
        this.settings = settings;
        JWSAlgorithm algorithm = settings.usesSharedSecret() ? JWSAlgorithm.HS256 : JWSAlgorithm.RS256;
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        // Pin the algorithm — the key selector accepts ONLY this alg, closing the RS256<->HS256
        // confusion / "alg:none" attacks regardless of what the token header claims.
        jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(algorithm, keySource));
        jwtProcessor.setJWTClaimsSetVerifier(buildClaimsVerifier(settings));
        this.processor = jwtProcessor;
    }

    /**
     * RS256 verification against a single LOCAL public key held in memory — the offline
     * counterpart to JWKS. Verifies your own self-issued tokens with just the public key (no
     * network). The key's {@code kid} drives rotation: keep old + new public keys to verify
     * tokens minted under either during a rollover.
     *
     * @param settings  use {@link IdpProvider#selfLocalRsa} (no remote source set)
     * @param publicKey the public RSA key (e.g. from {@link RsaKeys#verificationKey})
     */
    public static JwtVerifier localRsa(JwtVerifierSettings settings, RSAKey publicKey) {
        return new JwtVerifier(settings, new ImmutableJWKSet<>(new JWKSet(publicKey)));
    }

    /**
     * RS256 verification against SEVERAL local public keys — for KEY ROTATION. The token's {@code kid}
     * selects the matching key, so during a rollover you keep BOTH the previous and the new public key in
     * the set: tokens minted under either {@code kid} still verify until they expire (no mass logout).
     * Once every token minted under the old key has expired, drop it from the list.
     *
     * @param settings   use {@link IdpProvider#selfLocalRsa}
     * @param publicKeys the accepted public keys, each carrying its own {@code kid}
     */
    public static JwtVerifier localRsa(JwtVerifierSettings settings, List<RSAKey> publicKeys) {
        List<JWK> jwks = new ArrayList<>(publicKeys);
        return new JwtVerifier(settings, new ImmutableJWKSet<>(new JWKSet(jwks)));
    }

    /**
     * RS256 verification against a public key loaded from a PEM FILE on the filesystem — the
     * jr-first one-liner for "verify my own tokens with the public key I generated".
     *
     * @param issuer        expected {@code iss} ({@code null} skips the check)
     * @param audience      expected {@code aud} ({@code null} skips the check)
     * @param keyId         expected key id for rotation ({@code null} if you don't use {@code kid})
     * @param publicKeyPath filesystem path to the X.509 public PEM ({@code BEGIN PUBLIC KEY})
     */
    public static JwtVerifier rsaFromPem(String issuer, String audience, String keyId, String publicKeyPath) {
        return localRsa(IdpProvider.selfLocalRsa(issuer, audience), RsaKeys.verificationKey(publicKeyPath, keyId));
    }

    /**
     * Verify the token and extract identity. Validates signature, issuer, audience and
     * expiry (with clock skew) per {@link JwtVerifierSettings}.
     *
     * @throws TokenVerificationException if the token is invalid/expired/wrong issuer or audience
     * @throws AuthToolkitException       if the key source/JWKS cannot be reached
     */
    public IdentityClaims verify(String token) {
        try {
            JWTClaimsSet claims = processor.process(token, null);
            String externalId = firstNonBlank(claims.getStringClaim(settings.externalIdClaim()), claims.getSubject());
            if (externalId == null || externalId.isBlank()) {
                throw new TokenVerificationException("token has no subject / " + settings.externalIdClaim() + " claim");
            }
            String email = claims.getStringClaim(settings.emailClaim());
            String displayName = claims.getStringClaim(settings.nameClaim());
            return new IdentityClaims(claims.getIssuer(), externalId, email, displayName, claims.getClaims());
        } catch (ParseException | BadJOSEException e) {
            throw new TokenVerificationException("JWT rejected: " + e.getMessage(), e);
        } catch (JOSEException e) {
            throw new AuthToolkitException("JWT verification infrastructure error (key source unreachable?)", e);
        }
    }

    private static JWKSource<SecurityContext> defaultKeySource(JwtVerifierSettings settings) {
        if (settings.usesSharedSecret()) {
            return new ImmutableSecret<>(settings.hmacSecret().getBytes(StandardCharsets.UTF_8));
        }
        if (settings.jwksUri() == null || settings.jwksUri().isBlank()) {
            throw new AuthToolkitException(
                    "No key source set. Use a JWKS endpoint or HMAC secret, or for a local public "
                    + "key call JwtVerifier.localRsa(...) / JwtVerifier.rsaFromPem(...) instead.");
        }
        try {
            URL url = URI.create(settings.jwksUri()).toURL();
            return JWKSourceBuilder.<SecurityContext>create(url).build();
        } catch (MalformedURLException | IllegalArgumentException e) {
            throw new AuthToolkitException("Invalid jwksUri: " + settings.jwksUri(), e);
        }
    }

    private static DefaultJWTClaimsVerifier<SecurityContext> buildClaimsVerifier(JwtVerifierSettings settings) {
        JWTClaimsSet.Builder exactMatch = new JWTClaimsSet.Builder();
        if (settings.issuer() != null && !settings.issuer().isBlank()) {
            exactMatch.issuer(settings.issuer());
        }
        Set<String> requiredClaims = Set.of(settings.externalIdClaim());
        if (settings.audience() != null && !settings.audience().isBlank()) {
            return new DefaultJWTClaimsVerifier<>(settings.audience(), exactMatch.build(), requiredClaims);
        }
        return new DefaultJWTClaimsVerifier<>(exactMatch.build(), requiredClaims);
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        return b;
    }
}
