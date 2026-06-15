package com.github.calcifux.authtoolkit.spring;

import com.github.calcifux.authtoolkit.AuthPrincipal;
import com.github.calcifux.authtoolkit.IdentityClaims;
import com.github.calcifux.authtoolkit.PrincipalMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Smoke tests for the auto-configuration: the resolver filter is always present, and the
 * adapters appear only when their {@code enabled} flag (and required app beans) are set.
 */
class AuthToolkitAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthToolkitAutoConfiguration.class));

    @Test
    void registersTheResolverFilterByDefault() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(AuthResolverFilter.class);
            assertThat(context).doesNotHaveBean(HeaderAuthPrincipalResolver.class);
        });
    }

    @Test
    void enablesHeaderAdapterByProperty() {
        runner.withPropertyValues("auth.toolkit.header.enabled=true")
                .run(context -> assertThat(context).hasSingleBean(HeaderAuthPrincipalResolver.class));
    }

    @Test
    void wiresCookieSessionAdapterWhenAppBeansPresent() {
        runner.withPropertyValues("auth.toolkit.session.enabled=true")
                .withUserConfiguration(AppBeans.class)
                .run(context -> assertThat(context).hasSingleBean(CookieSessionAuthPrincipalResolver.class));
    }

    @Configuration
    static class AppBeans {
        @Bean
        PrincipalMapper principalMapper() {
            return claims -> AuthPrincipal.user(UUID.randomUUID());
        }

        @Bean
        com.github.calcifux.authtoolkit.TokenIntrospector tokenIntrospector() {
            return token -> java.util.Optional.of(
                    new IdentityClaims("local", token, null, null, java.util.Map.of()));
        }
    }
}
