package com.github.calcifux.authtoolkit.quarkus.core;

import com.github.calcifux.authtoolkit.Ability;
import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.quarkus.Auth;
import com.github.calcifux.authtoolkit.quarkus.AuthContext;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Gemelo gestionado por CDI de la fachada estática {@link Auth}, para recursos y servicios que
 * prefieren la inyección sobre las llamadas estáticas. Contraparte del lado de lectura de
 * {@code RemoteUploadCdiService} / {@code RemoteDownloadJaxRsService}.
 *
 * <p>Sin estado: cada lectura pasa por el {@link AuthContext} por petición que el filtro de
 * petición de la aplicación pobló, de modo que una única instancia {@code @ApplicationScoped} es
 * correcta (la identidad vive en el contexto thread-local, no en el bean).</p>
 *
 * <pre>{@code
 * @Inject AuthCdiService auth;
 * if (!auth.can("publish", "article")) throw new ForbiddenException();
 * }</pre>
 *
 * @since 0.1.4
 */
@ApplicationScoped
public class AuthCdiService {

    public Optional<AuthPrincipal> principal() {
        return Auth.principal();
    }

    public Optional<UUID> userId() {
        return Auth.userId();
    }

    public boolean isAuthenticated() {
        return Auth.isAuthenticated();
    }

    public boolean isOperator() {
        return Auth.isOperator();
    }

    public Set<String> roles() {
        return Auth.roles();
    }

    public List<Ability> abilities() {
        return Auth.abilities();
    }

    /** Comprobación RBAC: ¿tiene el principal actual {@code action} sobre {@code subject}? */
    public boolean can(String action, String subject) {
        return Auth.can(action, subject);
    }
}
