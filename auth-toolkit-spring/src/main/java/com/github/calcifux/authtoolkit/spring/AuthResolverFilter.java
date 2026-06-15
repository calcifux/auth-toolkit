package com.github.calcifux.authtoolkit.spring;

import com.github.calcifux.authtoolkit.AbilityResolver;
import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.AuthorizationProfile;
import com.github.calcifux.authtoolkit.TokenVerificationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * Populates {@link AuthContext} by running the ordered {@link AuthPrincipalResolver}
 * chain: the first adapter that resolves wins (header → bearer-JWT → cookie-session).
 * If an {@link AbilityResolver} bean exists, the principal's roles/abilities are resolved
 * once here and cached for the request so the {@link Auth} facade is a pure thread-local read.
 *
 * <p>Failure handling: a present-but-invalid token ({@link TokenVerificationException})
 * short-circuits to 401; no credential leaves the request anonymous (downstream guards
 * decide). The context is always cleared in {@code finally}.</p>
 */
public class AuthResolverFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthResolverFilter.class);

    private final List<AuthPrincipalResolver> resolvers;
    private final ObjectProvider<AbilityResolver> abilityResolver;
    private final List<String> skipPaths;

    public AuthResolverFilter(
            List<AuthPrincipalResolver> resolvers,
            ObjectProvider<AbilityResolver> abilityResolver,
            List<String> skipPaths) {
        this.resolvers = resolvers.stream()
                .sorted(Comparator.comparingInt(AuthPrincipalResolver::order))
                .toList();
        this.abilityResolver = abilityResolver;
        this.skipPaths = (skipPaths == null) ? List.of() : List.copyOf(skipPaths);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        try {
            try {
                populateContext(request);
            } catch (TokenVerificationException e) {
                // Credential present but invalid → 401 (do NOT downgrade to anonymous).
                log.debug("Rejecting request: {}", e.getMessage());
                writeUnauthorized(response, e.getMessage());
                return;
            }
            filterChain.doFilter(request, response);
        } finally {
            AuthContext.clear();
        }
    }

    private void populateContext(HttpServletRequest request) {
        for (AuthPrincipalResolver resolver : resolvers) {
            Optional<AuthPrincipal> resolved = resolver.resolve(request);
            if (resolved.isPresent()) {
                AuthPrincipal principal = resolved.get();
                AuthorizationProfile profile = resolveProfile(principal);
                AuthContext.set(principal, profile);
                return;
            }
        }
    }

    private AuthorizationProfile resolveProfile(AuthPrincipal principal) {
        AbilityResolver resolver = abilityResolver.getIfAvailable();
        if (resolver == null) {
            return AuthorizationProfile.empty();
        }
        return resolver.resolve(principal);
    }

    private void writeUnauthorized(HttpServletResponse response, String detail) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/problem+json");
        String safeDetail = (detail == null ? "Unauthorized" : detail).replace("\"", "'");
        response.getWriter().write(
                "{\"status\":401,\"title\":\"Unauthorized\",\"detail\":\"" + safeDetail + "\"}");
    }

    /** Skip the filter for configured prefixes (typically {@code /actuator}). */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        for (String prefix : skipPaths) {
            if (uri.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
