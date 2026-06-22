package com.github.calcifux.authtoolkit.spring.method;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authorization.method.PrePostTemplateDefaults;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Opt-in method-security bridge. Activates only when Spring Security is on the classpath AND
 * {@code auth.toolkit.method-security.enabled=true}. Enables {@code @PreAuthorize} and wires:
 * <ul>
 *   <li>the {@link SecurityContextBridgeFilter} (roles/abilities → Spring authorities);</li>
 *   <li>the {@code authz} bean for {@code @PreAuthorize("@authz.can('publish','article')")};</li>
 *   <li>a default {@link AbilityAuthorityNaming} ({@code action:subject}) — override with your own bean.</li>
 * </ul>
 */
@Slf4j
@AutoConfiguration
@ConditionalOnClass(name = "org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity")
@ConditionalOnProperty(prefix = "auth.toolkit.method-security", name = "enabled", havingValue = "true")
@EnableMethodSecurity
public class AuthToolkitMethodSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AbilityAuthorityNaming abilityAuthorityNaming() {
        return AbilityAuthorityNaming.defaultNaming();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityContextBridgeFilter authToolkitSecurityContextBridgeFilter(AbilityAuthorityNaming naming) {
        log.info("[auth-toolkit] method-security bridge active (@PreAuthorize over toolkit roles/abilities)");
        return new SecurityContextBridgeFilter(naming);
    }

    @Bean("authz")
    @ConditionalOnMissingBean(name = "authz")
    public AuthzExpression authzExpression() {
        return new AuthzExpression();
    }

    /**
     * Enables {@code {action}}/{@code {subject}} placeholder substitution in meta-annotations like
     * {@link AuthCan} (which is a meta-{@code @PreAuthorize("@authz.can('{action}','{subject}')")}).
     */
    @Bean
    @ConditionalOnMissingBean
    public PrePostTemplateDefaults authToolkitPrePostTemplateDefaults() {
        return new PrePostTemplateDefaults();
    }
}
