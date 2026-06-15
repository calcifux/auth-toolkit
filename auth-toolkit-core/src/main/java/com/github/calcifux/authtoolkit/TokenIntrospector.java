package com.github.calcifux.authtoolkit;

import java.util.Optional;

/**
 * Validates an OPAQUE token (no signature to verify) and returns its identity, or
 * {@link Optional#empty()} if the token is unknown/expired. This is the branch for
 * tokens that are NOT JWTs:
 * <ul>
 *   <li>our own opaque HttpOnly session cookie → DB lookup of the session hash;</li>
 *   <li>Laravel Sanctum tokens → SHA-256-hash lookup in {@code personal_access_tokens};</li>
 *   <li>any RFC 7662 introspection endpoint.</li>
 * </ul>
 *
 * <p>Implemented by the application (it owns the session/token store). The cookie and
 * Sanctum adapters delegate here.</p>
 */
@FunctionalInterface
public interface TokenIntrospector {

    /** Resolve the opaque token to identity claims, or empty if invalid/expired. */
    Optional<IdentityClaims> introspect(String token);
}
