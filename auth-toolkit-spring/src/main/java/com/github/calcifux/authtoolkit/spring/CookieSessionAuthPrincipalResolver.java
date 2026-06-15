package com.github.calcifux.authtoolkit.spring;

import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.IdentityClaims;
import com.github.calcifux.authtoolkit.PrincipalMapper;
import com.github.calcifux.authtoolkit.TokenIntrospector;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

/**
 * Resolves an OPAQUE session token from an HttpOnly cookie: hands the cookie value to
 * the application's {@link TokenIntrospector} (DB lookup of the session hash, or a
 * Laravel Sanctum {@code personal_access_tokens} lookup), then maps the resulting
 * {@link IdentityClaims} to a local {@link AuthPrincipal}.
 *
 * <p>This is the SPA's front-channel: the browser only ever holds the opaque cookie.
 * An absent OR unknown/expired cookie → empty (anonymous): session expiry is normal, so
 * the app/guard sends the user to login rather than erroring with 401.</p>
 */
public class CookieSessionAuthPrincipalResolver implements AuthPrincipalResolver {

    private final TokenIntrospector introspector;
    private final PrincipalMapper principalMapper;
    private final String cookieName;

    public CookieSessionAuthPrincipalResolver(
            TokenIntrospector introspector, PrincipalMapper principalMapper, String cookieName) {
        this.introspector = introspector;
        this.principalMapper = principalMapper;
        this.cookieName = cookieName;
    }

    @Override
    public int order() {
        return 30;
    }

    @Override
    public Optional<AuthPrincipal> resolve(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        String token = null;
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                token = cookie.getValue();
                break;
            }
        }
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        // Opaque token: unknown/expired → empty (anonymous), not an error.
        Optional<IdentityClaims> claims = introspector.introspect(token);
        return claims.map(principalMapper::map);
    }
}
