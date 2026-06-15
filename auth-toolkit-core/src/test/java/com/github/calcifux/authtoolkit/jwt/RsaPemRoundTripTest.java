package com.github.calcifux.authtoolkit.jwt;

import com.github.calcifux.authtoolkit.IdentityClaims;
import com.github.calcifux.authtoolkit.TokenVerificationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Proves the full RS256-from-PEM-files path: generate a keypair to disk, sign with the private
 * PEM ({@link JwtIssuer#rsaFromPem}) and verify with ONLY the public PEM
 * ({@link JwtVerifier#rsaFromPem}) — no JWKS endpoint, no shared secret. This is the offline,
 * single-service shape used by the on-prem session cookie.
 */
class RsaPemRoundTripTest {

    private static final String ISSUER = "workorder";
    private static final String AUDIENCE = "workorder-api";
    private static final String KID = "test-kid-1";

    private String privateKeyPath;
    private String publicKeyPath;

    @BeforeEach
    void generateKeys(@TempDir Path dir) {
        Path priv = dir.resolve("private.pem");
        Path pub = dir.resolve("public.pem");
        RsaKeyGenerator.writeKeypair(2048, priv, pub);
        this.privateKeyPath = priv.toString();
        this.publicKeyPath = pub.toString();
    }

    @Test
    void signsWithPrivatePemAndVerifiesWithPublicPem() {
        JwtIssuer issuer = JwtIssuer.rsaFromPem(ISSUER, KID, privateKeyPath, publicKeyPath);
        JwtVerifier verifier = JwtVerifier.rsaFromPem(ISSUER, AUDIENCE, KID, publicKeyPath);

        String token = issuer.issue("user-123", AUDIENCE, Duration.ofMinutes(10),
                Map.of("email", "maria@example.test", "name", "Maria"));

        IdentityClaims claims = verifier.verify(token);

        assertThat(claims.externalId()).isEqualTo("user-123");
        assertThat(claims.issuer()).isEqualTo(ISSUER);
        assertThat(claims.email()).isEqualTo("maria@example.test");
        assertThat(claims.displayName()).isEqualTo("Maria");
    }

    @Test
    void verifierNeedsOnlyThePublicKey() {
        // The verifier is built from the public PEM alone — a second service can verify without
        // ever holding signing power (the whole point of RS256 over a shared secret).
        JwtVerifier publicOnly = JwtVerifier.rsaFromPem(ISSUER, AUDIENCE, KID, publicKeyPath);
        String token = JwtIssuer.rsaFromPem(ISSUER, KID, privateKeyPath, publicKeyPath)
                .issue("user-7", AUDIENCE, Duration.ofMinutes(5), Map.of());

        assertThat(publicOnly.verify(token).externalId()).isEqualTo("user-7");
    }

    @Test
    void rejectsExpiredToken() {
        JwtIssuer issuer = JwtIssuer.rsaFromPem(ISSUER, KID, privateKeyPath, publicKeyPath);
        JwtVerifier verifier = JwtVerifier.rsaFromPem(ISSUER, AUDIENCE, KID, publicKeyPath);

        String expired = issuer.issue("user-123", AUDIENCE, Duration.ofMinutes(-5), Map.of());
        assertThatThrownBy(() -> verifier.verify(expired))
                .isInstanceOf(TokenVerificationException.class);
    }

    @Test
    void rejectsTamperedSignature() {
        JwtIssuer issuer = JwtIssuer.rsaFromPem(ISSUER, KID, privateKeyPath, publicKeyPath);
        JwtVerifier verifier = JwtVerifier.rsaFromPem(ISSUER, AUDIENCE, KID, publicKeyPath);

        String token = issuer.issue("user-123", AUDIENCE, Duration.ofMinutes(10), Map.of());
        String tampered = token.substring(0, token.length() - 2) + "xy";
        assertThatThrownBy(() -> verifier.verify(tampered))
                .isInstanceOf(TokenVerificationException.class);
    }

    @Test
    void rejectsTokenSignedByADifferentKey(@TempDir Path otherDir) {
        // A token minted by an UNRELATED keypair must not verify against our public key.
        Path otherPriv = otherDir.resolve("private.pem");
        Path otherPub = otherDir.resolve("public.pem");
        RsaKeyGenerator.writeKeypair(2048, otherPriv, otherPub);

        String foreign = JwtIssuer.rsaFromPem(ISSUER, KID, otherPriv.toString(), otherPub.toString())
                .issue("user-123", AUDIENCE, Duration.ofMinutes(10), Map.of());

        JwtVerifier verifier = JwtVerifier.rsaFromPem(ISSUER, AUDIENCE, KID, publicKeyPath);
        assertThatThrownBy(() -> verifier.verify(foreign))
                .isInstanceOf(TokenVerificationException.class);
    }

    @Test
    void verifiesTokensFromEitherKeyDuringRotation(@TempDir Path dir) {
        // Two independent keypairs with distinct kids = the "old" and "new" rotation keys.
        Path oldPriv = dir.resolve("old-private.pem"), oldPub = dir.resolve("old-public.pem");
        Path newPriv = dir.resolve("new-private.pem"), newPub = dir.resolve("new-public.pem");
        RsaKeyGenerator.writeKeypair(2048, oldPriv, oldPub);
        RsaKeyGenerator.writeKeypair(2048, newPriv, newPub);

        JwtIssuer oldIssuer = JwtIssuer.rsaFromPem(ISSUER, "kid-old", oldPriv.toString(), oldPub.toString());
        JwtIssuer newIssuer = JwtIssuer.rsaFromPem(ISSUER, "kid-new", newPriv.toString(), newPub.toString());

        // Verifier holds BOTH public keys (overlap window) — it selects by the token's kid.
        JwtVerifier verifier = JwtVerifier.localRsa(
                IdpProvider.selfLocalRsa(ISSUER, AUDIENCE),
                List.of(RsaKeys.verificationKey(oldPub.toString(), "kid-old"),
                        RsaKeys.verificationKey(newPub.toString(), "kid-new")));

        String oldToken = oldIssuer.issue("u1", AUDIENCE, Duration.ofMinutes(10), Map.of());
        String newToken = newIssuer.issue("u2", AUDIENCE, Duration.ofMinutes(10), Map.of());

        assertThat(verifier.verify(oldToken).externalId()).isEqualTo("u1"); // kid viejo sigue válido
        assertThat(verifier.verify(newToken).externalId()).isEqualTo("u2"); // kid nuevo válido

        // Un token de una TERCERA llave desconocida (aunque reuse un kid conocido) es rechazado.
        Path strayPriv = dir.resolve("stray-private.pem"), strayPub = dir.resolve("stray-public.pem");
        RsaKeyGenerator.writeKeypair(2048, strayPriv, strayPub);
        String stray = JwtIssuer.rsaFromPem(ISSUER, "kid-old", strayPriv.toString(), strayPub.toString())
                .issue("u3", AUDIENCE, Duration.ofMinutes(10), Map.of());
        assertThatThrownBy(() -> verifier.verify(stray)).isInstanceOf(TokenVerificationException.class);
    }

    @Test
    void publicJwksJsonExposesOnlyPublicParams() {
        String jwks = RsaKeys.publicJwksJson(RsaKeys.verificationKey(publicKeyPath, KID));
        assertThat(jwks).contains("\"keys\"").contains("\"kid\":\"" + KID + "\"").contains("\"kty\":\"RSA\"");
        // No private params leaked.
        assertThat(jwks).doesNotContain("\"d\":").doesNotContain("\"p\":").doesNotContain("\"q\":");
    }
}
