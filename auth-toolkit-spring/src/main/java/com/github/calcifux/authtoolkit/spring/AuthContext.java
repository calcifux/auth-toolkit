package com.github.calcifux.authtoolkit.spring;

import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.AuthorizationProfile;

import java.util.Optional;

/**
 * Per-thread holder of the resolved identity ({@link AuthPrincipal}) and its
 * authorization snapshot ({@link AuthorizationProfile}). Populated by
 * {@link AuthResolverFilter} at the start of each request and cleared in {@code finally}
 * to avoid leaking across pooled servlet threads. Read it through the {@link Auth} facade.
 */
public final class AuthContext {

    private static final ThreadLocal<AuthPrincipal> PRINCIPAL = new ThreadLocal<>();
    private static final ThreadLocal<AuthorizationProfile> PROFILE = new ThreadLocal<>();

    private AuthContext() {
    }

    /** Set by the filter once the chain resolves a principal. Package-private on purpose. */
    static void set(AuthPrincipal principal, AuthorizationProfile profile) {
        PRINCIPAL.set(principal);
        PROFILE.set(profile != null ? profile : AuthorizationProfile.empty());
    }

    static void clear() {
        PRINCIPAL.remove();
        PROFILE.remove();
    }

    public static Optional<AuthPrincipal> principal() {
        return Optional.ofNullable(PRINCIPAL.get());
    }

    public static AuthorizationProfile profile() {
        AuthorizationProfile profile = PROFILE.get();
        return profile != null ? profile : AuthorizationProfile.empty();
    }
}
