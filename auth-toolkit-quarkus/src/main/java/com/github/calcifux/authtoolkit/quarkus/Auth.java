package com.github.calcifux.authtoolkit.quarkus;

import com.github.calcifux.authtoolkit.Ability;
import com.github.calcifux.authtoolkit.AccessEvaluator;
import com.github.calcifux.authtoolkit.AuthPrincipal;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Fachada estática, al estilo de Laravel, sobre la identidad y las capacidades de la petición
 * actual — el lado de lectura del toolkit sobre un runtime CDI. Refleja la fachada {@code Auth}
 * de Spring y las fachadas {@code Uploads}/{@code Downloads}.
 *
 * <pre>{@code
 * if (!Auth.can("publish", "article")) throw new ForbiddenException();
 * UUID me = Auth.userId().orElseThrow();
 * }</pre>
 *
 * <p>Lee el {@link AuthContext} que el filtro de petición de la aplicación pobló; las capacidades
 * provienen del {@code AbilityResolver} de la aplicación. Este es uno de los dos puntos de
 * aplicación (el otro es el control de la interfaz de usuario en la SPA) — ninguno reemplaza al
 * otro. Para un acceso por inyección utiliza
 * {@link com.github.calcifux.authtoolkit.quarkus.core.AuthCdiService}.</p>
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

    /** Códigos de rol de grano grueso (visualización/etiquetas). NO controles la interfaz de usuario ni la lógica por nombres — utiliza {@link #can}. */
    public static Set<String> roles() {
        return AuthContext.profile().roles();
    }

    public static List<Ability> abilities() {
        return AuthContext.profile().abilities();
    }

    /** Comprobación RBAC: ¿tiene el principal actual {@code action} sobre {@code subject}? */
    public static boolean can(String action, String subject) {
        return AccessEvaluator.can(AuthContext.profile().abilities(), action, subject);
    }
}
