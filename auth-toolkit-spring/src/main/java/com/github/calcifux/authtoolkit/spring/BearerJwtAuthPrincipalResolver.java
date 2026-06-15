package com.github.calcifux.authtoolkit.spring;

import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.IdentityClaims;
import com.github.calcifux.authtoolkit.PrincipalMapper;
import com.github.calcifux.authtoolkit.jwt.JwtVerifier;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

/**
 * Resolves a {@code Authorization: Bearer <jwt>} token: verifies it with the
 * {@link JwtVerifier} (self / Passport / Entra / OIDC) and maps the resulting
 * {@link IdentityClaims} to a local {@link AuthPrincipal} via the application's
 * {@link PrincipalMapper} (JIT provisioning / linking by {@code (issuer, externalId)}).
 *
 * <p>No bearer header → empty (anonymous, try next). A present-but-invalid token makes
 * {@link JwtVerifier#verify} throw {@code TokenVerificationException} → the filter returns 401.</p>
 */
public class BearerJwtAuthPrincipalResolver implements AuthPrincipalResolver {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtVerifier verifier;
    private final PrincipalMapper principalMapper;
    private final String headerName;

    public BearerJwtAuthPrincipalResolver(JwtVerifier verifier, PrincipalMapper principalMapper, String headerName) {
        this.verifier = verifier;
        this.principalMapper = principalMapper;
        this.headerName = (headerName == null || headerName.isBlank()) ? "Authorization" : headerName;
    }

    @Override
    public int order() {
        return 20;
    }

    @Override
    public Optional<AuthPrincipal> resolve(HttpServletRequest request) {
        String header = request.getHeader(headerName);
        if (header == null || !header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return Optional.empty();
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        if (token.isEmpty()) {
            return Optional.empty();
        }
        IdentityClaims claims = verifier.verify(token); // throws on invalid → 401 upstream
        return Optional.of(principalMapper.map(claims));
    }
}
