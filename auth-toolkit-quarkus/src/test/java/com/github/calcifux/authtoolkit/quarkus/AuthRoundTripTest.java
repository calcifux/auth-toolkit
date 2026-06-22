package com.github.calcifux.authtoolkit.quarkus;

import com.github.calcifux.authtoolkit.Ability;
import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.AuthorizationProfile;
import com.github.calcifux.authtoolkit.quarkus.core.AuthCdiService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifica el ciclo completo de "trae tu propio resolver": poblar {@link AuthContext} como lo
 * haría un filtro de la aplicación, leerlo de vuelta a través de la fachada estática {@link Auth}
 * y del {@link AuthCdiService} de estilo inyectable, y confirmar que {@link AuthContext#clear()}
 * no deja residuos en el hilo de trabajo.
 */
class AuthRoundTripTest {

    private final AuthCdiService authCdiService = new AuthCdiService();

    @AfterEach
    void tearDown() {
        AuthContext.clear();
    }

    @Test
    void facadeReadsThePopulatedContext() {
        UUID userId = UUID.randomUUID();
        AuthPrincipal principal = AuthPrincipal.operator(userId);
        AuthorizationProfile profile =
                new AuthorizationProfile(Set.of("EDITOR"), List.of(Ability.of("publish", "article")));

        AuthContext.populate(principal, profile);

        assertThat(Auth.isAuthenticated()).isTrue();
        assertThat(Auth.userId()).contains(userId);
        assertThat(Auth.isOperator()).isTrue();
        assertThat(Auth.roles()).containsExactly("EDITOR");
        assertThat(Auth.can("publish", "article")).isTrue();
        assertThat(Auth.can("delete", "article")).isFalse();
    }

    @Test
    void cdiServiceDelegatesToTheSameContext() {
        UUID userId = UUID.randomUUID();
        AuthContext.populate(
                AuthPrincipal.user(userId),
                new AuthorizationProfile(Set.of("VIEWER"), List.of(Ability.of("read", "article"))));

        assertThat(authCdiService.isAuthenticated()).isTrue();
        assertThat(authCdiService.userId()).contains(userId);
        assertThat(authCdiService.isOperator()).isFalse();
        assertThat(authCdiService.can("read", "article")).isTrue();
        assertThat(authCdiService.can("publish", "article")).isFalse();
    }

    @Test
    void clearLeavesNoResidueOnTheThread() {
        AuthContext.populate(AuthPrincipal.user(UUID.randomUUID()), AuthorizationProfile.empty());
        AuthContext.clear();

        assertThat(Auth.isAuthenticated()).isFalse();
        assertThat(Auth.principal()).isEmpty();
        assertThat(Auth.roles()).isEmpty();
        assertThat(Auth.can("read", "article")).isFalse();
    }
}
