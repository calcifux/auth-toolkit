package com.github.calcifux.authtoolkit.quarkus;

import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.AuthorizationProfile;

import java.util.Optional;

/**
 * Contenedor por petición de la identidad resuelta ({@link AuthPrincipal}) y su
 * instantánea de autorización ({@link AuthorizationProfile}), leído a través de la fachada
 * {@link Auth} o del inyectable {@link com.github.calcifux.authtoolkit.quarkus.core.AuthCdiService}.
 *
 * <p><b>Trae tu propio resolver.</b> A diferencia del adaptador de Spring, el adaptador de Quarkus
 * no incluye ningún filtro: la aplicación pobla este contexto desde su PROPIO
 * {@code ContainerRequestFilter} de JAX-RS mediante
 * {@link #populate(AuthPrincipal, AuthorizationProfile)} y DEBE limpiarlo en el
 * {@code ContainerResponseFilter} correspondiente (o en un {@code finally}) mediante
 * {@link #clear()} para que el thread-local no se filtre entre los hilos de trabajo agrupados.</p>
 *
 * <pre>{@code
 * // filtro de petición (recursos bloqueantes / @RunOnVirtualThread)
 * AuthContext.populate(principal, profile);
 * // filtro de respuesta
 * AuthContext.clear();
 * }</pre>
 *
 * <p>Es thread-local por diseño: está orientado a endpoints bloqueantes (hilo de trabajo de
 * RESTEasy o un hilo virtual por petición), donde el filtro de petición, el método del recurso
 * y el filtro de respuesta se ejecutan en el mismo hilo. Para una canalización totalmente reactiva
 * que salta entre hilos del bucle de eventos, propágalo con
 * {@code quarkus-smallrye-context-propagation} o mueve el contenedor a un bean
 * {@code @RequestScoped}.</p>
 */
public final class AuthContext {

    private static final ThreadLocal<AuthPrincipal> PRINCIPAL = new ThreadLocal<>();
    private static final ThreadLocal<AuthorizationProfile> PROFILE = new ThreadLocal<>();

    private AuthContext() {
    }

    /**
     * Pobla el contexto desde tu propio resolver/filtro. DEBE emparejarse con {@link #clear()}
     * en el filtro de respuesta correspondiente / {@code finally} para que el thread-local no se
     * filtre entre los hilos de trabajo agrupados.
     */
    public static void populate(AuthPrincipal principal, AuthorizationProfile profile) {
        PRINCIPAL.set(principal);
        PROFILE.set(profile != null ? profile : AuthorizationProfile.empty());
    }

    /** Limpia el contexto por petición. Llama a esto en el filtro de respuesta / en un {@code finally}. */
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
