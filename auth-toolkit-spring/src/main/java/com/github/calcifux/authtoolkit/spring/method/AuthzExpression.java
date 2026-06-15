package com.github.calcifux.authtoolkit.spring.method;

import com.github.calcifux.authtoolkit.spring.Auth;

/**
 * SpEL-callable authorization helper, registered as the bean named {@code authz}, so the
 * {@code (action, subject)} ability model can be used directly in method-security expressions
 * without flattening to authority strings:
 *
 * <pre>{@code
 * @PreAuthorize("@authz.can('publish', 'article')")
 * void publish(...) { ... }
 * }</pre>
 *
 * Reads the per-request {@code AuthContext} through the {@link Auth} facade.
 */
public class AuthzExpression {

    /** Does the current principal have {@code action} on {@code subject}? */
    public boolean can(String action, String subject) {
        return Auth.can(action, subject);
    }

    public boolean isAuthenticated() {
        return Auth.isAuthenticated();
    }

    public boolean isOperator() {
        return Auth.isOperator();
    }
}
