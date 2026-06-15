package com.github.calcifux.authtoolkit.jwt;

import com.github.calcifux.authtoolkit.IdentityClaims;
import com.github.calcifux.authtoolkit.TokenVerificationException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Issue a self-signed (HS256) token and verify it round-trips through the toolkit's own
 * verifier — proving the issuer/verifier pair and the issuer/audience/expiry checks work.
 */
class JwtRoundTripTest {

    // HS256 requires a secret of at least 256 bits (32 chars).
    private static final String SECRET = "test-secret-test-secret-test-secret-1234";
    private static final String ISSUER = "https://auth.example.test";
    private static final String AUDIENCE = "my-api";

    private final JwtIssuer issuer = JwtIssuer.hmac(ISSUER, SECRET);
    private final JwtVerifier verifier = new JwtVerifier(IdpProvider.selfHmac(ISSUER, AUDIENCE, SECRET));

    @Test
    void verifiesAValidTokenAndExtractsIdentity() {
        String token = issuer.issue("user-123", AUDIENCE, Duration.ofMinutes(10),
                Map.of("email", "maria@example.test", "name", "Maria"));

        IdentityClaims claims = verifier.verify(token);

        assertThat(claims.externalId()).isEqualTo("user-123");
        assertThat(claims.issuer()).isEqualTo(ISSUER);
        assertThat(claims.email()).isEqualTo("maria@example.test");
        assertThat(claims.displayName()).isEqualTo("Maria");
    }

    @Test
    void rejectsExpiredToken() {
        String expired = issuer.issue("user-123", AUDIENCE, Duration.ofMinutes(-5), Map.of());
        assertThatThrownBy(() -> verifier.verify(expired))
                .isInstanceOf(TokenVerificationException.class);
    }

    @Test
    void rejectsWrongAudience() {
        String otherAudience = issuer.issue("user-123", "some-other-api", Duration.ofMinutes(10), Map.of());
        assertThatThrownBy(() -> verifier.verify(otherAudience))
                .isInstanceOf(TokenVerificationException.class);
    }

    @Test
    void rejectsTamperedSignature() {
        String token = issuer.issue("user-123", AUDIENCE, Duration.ofMinutes(10), Map.of());
        String tampered = token.substring(0, token.length() - 2) + "xy";
        assertThatThrownBy(() -> verifier.verify(tampered))
                .isInstanceOf(TokenVerificationException.class);
    }
}
