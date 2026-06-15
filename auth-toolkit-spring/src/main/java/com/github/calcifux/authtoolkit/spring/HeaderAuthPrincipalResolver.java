package com.github.calcifux.authtoolkit.spring;

import com.github.calcifux.authtoolkit.AuthPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.UUID;

/**
 * Dev / trusted-proxy adapter: reads the LOCAL user id (and an optional role) straight
 * from request headers. Enable ONLY behind a trusted gateway or in development — it
 * trusts the caller. Gated by {@code auth.toolkit.header.enabled=true}.
 */
public class HeaderAuthPrincipalResolver implements AuthPrincipalResolver {

    private static final Logger log = LoggerFactory.getLogger(HeaderAuthPrincipalResolver.class);

    private final AuthToolkitProperties.Header config;

    public HeaderAuthPrincipalResolver(AuthToolkitProperties.Header config) {
        this.config = config;
    }

    @Override
    public int order() {
        return 10;
    }

    @Override
    public Optional<AuthPrincipal> resolve(HttpServletRequest request) {
        String userHeader = request.getHeader(config.getUser());
        if (userHeader == null || userHeader.isBlank()) {
            return Optional.empty();
        }
        UUID userId;
        try {
            userId = UUID.fromString(userHeader.trim());
        } catch (IllegalArgumentException e) {
            log.debug("Header {} is not a UUID: {}", config.getUser(), userHeader);
            return Optional.empty();
        }
        String roleHeader = request.getHeader(config.getRole());
        boolean operator = config.getOperatorRole().equalsIgnoreCase(roleHeader != null ? roleHeader.trim() : "");
        return Optional.of(new AuthPrincipal(userId, operator));
    }
}
