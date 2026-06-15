package com.github.calcifux.authtoolkit.spring;

import com.github.calcifux.authtoolkit.AuthPrincipal;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

/**
 * The one configurable contract: turn a request's credential into a normalized
 * {@link AuthPrincipal}. This is the Passport-strategy / Spring-AuthenticationProvider
 * shape distilled to one method.
 *
 * <p>Return semantics (standardized so failures are never silently downgraded):</p>
 * <ul>
 *   <li>{@link Optional#empty()} — no credential for me / anonymous; the chain tries the next adapter.</li>
 *   <li>present — resolved.</li>
 *   <li>throw {@link com.github.calcifux.authtoolkit.TokenVerificationException} — credential present but
 *       invalid (→ 401); throw {@link com.github.calcifux.authtoolkit.AuthToolkitException} — infrastructure failure.</li>
 * </ul>
 *
 * <p>New IdP = new adapter; selection is the ordered chain (lowest {@link #order()} first),
 * never branching inside one resolver.</p>
 */
public interface AuthPrincipalResolver {

    Optional<AuthPrincipal> resolve(HttpServletRequest request);

    /** Chain position; lower runs first. Header(10) → bearer-JWT(20) → cookie-session(30). */
    default int order() {
        return 100;
    }
}
