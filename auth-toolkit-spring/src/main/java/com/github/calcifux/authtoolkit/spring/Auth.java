package com.github.calcifux.authtoolkit.spring;

import com.github.calcifux.authtoolkit.AbilityResolver;
import com.github.calcifux.authtoolkit.Ability;
import com.github.calcifux.authtoolkit.AccessEvaluator;
import com.github.calcifux.authtoolkit.AuthPrincipal;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Static, Laravel-style facade over the current request's identity and abilities —
 * the read side of the toolkit. Mirrors the {@code Uploads}/{@code Downloads} facades.
 *
 * <pre>{@code
 * if (!Auth.can("approve", "workorder")) throw new ForbiddenException();
 * UUID me = Auth.userId().orElseThrow();
 * }</pre>
 *
 * <p>Reads the thread-local {@link AuthContext} the {@link AuthResolverFilter} populated;
 * the abilities come from the application's {@link AbilityResolver}. This is for
 * server-side checks AND for building the {@code /me} payload — but it is one of two
 * enforcement points: the UI gating in the SPA is the other, and neither replaces the
 * other.</p>
 */
public final class Auth {

    private Auth() {
    }

    public static Optional<AuthPrincipal> principal() {
        return AuthContext.principal();
    }

    public static Optional<UUID> userId() {
        return AuthContext.principal().map(AuthPrincipal::userId);
    }

    public static boolean isAuthenticated() {
        return AuthContext.principal().isPresent();
    }

    public static boolean isOperator() {
        return AuthContext.principal().map(AuthPrincipal::operator).orElse(false);
    }

    /** Coarse role codes (display/labels). Do NOT gate UI/logic on names — use {@link #can}. */
    public static Set<String> roles() {
        return AuthContext.profile().roles();
    }

    public static List<Ability> abilities() {
        return AuthContext.profile().abilities();
    }

    /** RBAC check: does the current principal have {@code action} on {@code subject}? */
    public static boolean can(String action, String subject) {
        return AccessEvaluator.can(AuthContext.profile().abilities(), action, subject);
    }
}
