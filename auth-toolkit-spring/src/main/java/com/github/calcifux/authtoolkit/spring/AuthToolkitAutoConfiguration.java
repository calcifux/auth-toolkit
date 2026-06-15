package com.github.calcifux.authtoolkit.spring;

import com.github.calcifux.authtoolkit.AbilityResolver;
import com.github.calcifux.authtoolkit.PrincipalMapper;
import com.github.calcifux.authtoolkit.TokenIntrospector;
import com.github.calcifux.authtoolkit.jwt.JwtVerifier;
import com.github.calcifux.authtoolkit.jwt.JwtVerifierSettings;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for auth-toolkit. Registers the {@link AuthResolverFilter} plus the
 * adapters whose {@code enabled} flag is set; provider selection is pure config. Every
 * bean is {@link ConditionalOnMissingBean}, so the application can override any of them
 * (its own resolver, its own {@link JwtVerifier} — e.g. a Firebase X.509 one).
 *
 * <p>The application supplies the local-data beans the adapters depend on:
 * {@link PrincipalMapper} (identity → local user), {@link TokenIntrospector} (opaque token
 * lookup) and {@link AbilityResolver} (roles/abilities). Identity comes from the token;
 * authorization is resolved locally.</p>
 */
@Slf4j
@AutoConfiguration
@EnableConfigurationProperties(AuthToolkitProperties.class)
public class AuthToolkitAutoConfiguration {

    /** The resolver-chain filter. Collects every {@link AuthPrincipalResolver} bean (may be none). */
    @Bean
    @ConditionalOnMissingBean
    public AuthResolverFilter authResolverFilter(
            ObjectProvider<AuthPrincipalResolver> resolvers,
            ObjectProvider<AbilityResolver> abilityResolver,
            AuthToolkitProperties properties) {
        log.info("[auth-toolkit] resolver-chain filter active (skip-paths={})", properties.getSkipPaths());
        return new AuthResolverFilter(resolvers.stream().toList(), abilityResolver, properties.getSkipPaths());
    }

    // ── Header adapter (dev / trusted proxy) ──────────────────────────────────
    @Bean
    @ConditionalOnProperty(prefix = "auth.toolkit.header", name = "enabled", havingValue = "true")
    @ConditionalOnMissingBean
    public HeaderAuthPrincipalResolver headerAuthPrincipalResolver(AuthToolkitProperties properties) {
        log.info("[auth-toolkit] header adapter enabled (user-header={})", properties.getHeader().getUser());
        return new HeaderAuthPrincipalResolver(properties.getHeader());
    }

    // ── Bearer-JWT adapter (self / Passport / Entra / OIDC) ───────────────────
    @Bean
    @ConditionalOnProperty(prefix = "auth.toolkit.jwt", name = "enabled", havingValue = "true")
    @ConditionalOnMissingBean
    public JwtVerifier authToolkitJwtVerifier(AuthToolkitProperties properties) {
        AuthToolkitProperties.Jwt jwt = properties.getJwt();
        JwtVerifierSettings settings = new JwtVerifierSettings(
                jwt.getIssuer(), jwt.getJwksUri(), jwt.getHmacSecret(), jwt.getAudience(),
                jwt.getExternalIdClaim(), jwt.getEmailClaim(), jwt.getNameClaim());
        log.info("[auth-toolkit] JWT verifier enabled (issuer={})", jwt.getIssuer());
        return new JwtVerifier(settings);
    }

    @Bean
    @ConditionalOnProperty(prefix = "auth.toolkit.jwt", name = "enabled", havingValue = "true")
    @ConditionalOnBean(PrincipalMapper.class)
    @ConditionalOnMissingBean
    public BearerJwtAuthPrincipalResolver bearerJwtAuthPrincipalResolver(
            JwtVerifier verifier, PrincipalMapper principalMapper, AuthToolkitProperties properties) {
        return new BearerJwtAuthPrincipalResolver(verifier, principalMapper, properties.getJwt().getBearerHeader());
    }

    // ── Opaque cookie-session adapter (SPA front-channel / Sanctum) ───────────
    @Bean
    @ConditionalOnProperty(prefix = "auth.toolkit.session", name = "enabled", havingValue = "true")
    @ConditionalOnBean({TokenIntrospector.class, PrincipalMapper.class})
    @ConditionalOnMissingBean
    public CookieSessionAuthPrincipalResolver cookieSessionAuthPrincipalResolver(
            TokenIntrospector introspector, PrincipalMapper principalMapper, AuthToolkitProperties properties) {
        log.info("[auth-toolkit] cookie-session adapter enabled (cookie={})", properties.getSession().getCookieName());
        return new CookieSessionAuthPrincipalResolver(introspector, principalMapper, properties.getSession().getCookieName());
    }
}
