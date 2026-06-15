package com.github.calcifux.authtoolkit.spring;

import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.AuthorizationProfile;

import java.util.Optional;

/**
 * Per-thread holder of the resolved identity ({@link AuthPrincipal}) and its
 * authorization snapshot ({@link AuthorizationProfile}). Populated by
 * {@link AuthResolverFilter} at the start of each request and cleared in {@code finally}
 * to avoid leaking across pooled servlet threads. Read it through the {@link Auth} facade.
 *
 * <p><b>Bring your own resolver:</b> an application that already resolves identity with its OWN
 * filter (and does NOT use {@link AuthResolverFilter}) can populate this context directly via
 * {@link #populate(AuthPrincipal, AuthorizationProfile)} — pairing it with {@link #clear()} in a
 * {@code finally}. That lets the toolkit's facade, {@code @CurrentUser} and method-security bridge
 * work on top of an existing auth pipeline without re-resolving the credential.</p>
 */
public final class AuthContext {

    private static final ThreadLocal<AuthPrincipal> PRINCIPAL = new ThreadLocal<>();
    private static final ThreadLocal<AuthorizationProfile> PROFILE = new ThreadLocal<>();

    private AuthContext() {
    }

    /** Set by the toolkit's own filter once the chain resolves a principal. */
    static void set(AuthPrincipal principal, AuthorizationProfile profile) {
        PRINCIPAL.set(principal);
        PROFILE.set(profile != null ? profile : AuthorizationProfile.empty());
    }

    /**
     * Populate the context from your OWN resolver/filter (when not using {@link AuthResolverFilter}).
     * MUST be paired with {@link #clear()} in a {@code finally} so the thread-local does not leak
     * across pooled servlet threads.
     */
    public static void populate(AuthPrincipal principal, AuthorizationProfile profile) {
        set(principal, profile);
    }

    /** Clears the per-thread context. Call this in a {@code finally} when you used {@link #populate}. */
    public static void clear() {
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
