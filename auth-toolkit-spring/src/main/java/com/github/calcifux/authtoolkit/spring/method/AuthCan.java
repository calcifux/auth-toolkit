package com.github.calcifux.authtoolkit.spring.method;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declarative ability-based authorization — an ergonomic alias for
 * {@code @PreAuthorize("@authz.can('action','subject')")}, the toolkit's CASL-style check. The twin of
 * {@code com.github.calcifux.authtoolkit.quarkus.method.AuthCan} on the Quarkus side.
 *
 * <pre>{@code
 *   @AuthCan(action = "publish", subject = "article")   // == @PreAuthorize("@authz.can('publish','article')")
 * }</pre>
 *
 * <p>Requires method security + the {@code authz} bean + meta-annotation template resolution — all wired by
 * {@link AuthToolkitMethodSecurityAutoConfiguration} (it registers a {@code PrePostTemplateDefaults} so the
 * {@code {action}}/{@code {subject}} placeholders are substituted). For multi-ability or role checks
 * ({@code hasAnyAuthority}, {@code hasRole}) use {@code @PreAuthorize} directly — the
 * {@code SecurityContextBridgeFilter} maps toolkit abilities/roles to Spring authorities.</p>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("@authz.can('{action}', '{subject}')")
public @interface AuthCan {

    String action();

    String subject();
}
