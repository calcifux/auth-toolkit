package com.github.calcifux.authtoolkit.quarkus.method;

import jakarta.enterprise.util.Nonbinding;
import jakarta.interceptor.InterceptorBinding;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Autorización DECLARATIVA por habilidad para Quarkus/CDI — el gemelo del
 * {@code @PreAuthorize("@authz.can(...)")} del lado Spring de este toolkit. Se pone en un método (o clase) de
 * recurso y el {@link AuthCanInterceptor} exige la habilidad ANTES del cuerpo: 403 ({@code ForbiddenException})
 * si falta. Evita el {@code if (!Auth.can(...)) throw new ForbiddenException(...)} imperativo en los controllers.
 *
 * <p>Equivalencias con los patrones de Spring (SpEL → Quarkus):</p>
 * <pre>
 *   {@literal @}PreAuthorize("{@literal @}authz.can('publish','article')")  → {@literal @}AuthCan(action = "publish", subject = "article")
 *   {@literal @}PreAuthorize("hasAuthority('publish:article')")     → {@literal @}AuthCan(action = "publish", subject = "article")
 *   {@literal @}PreAuthorize("hasAnyAuthority('a:b','c:d')")        → {@literal @}AuthCan(anyAuthority = {"a:b", "c:d"})
 *   {@literal @}PreAuthorize("hasRole('EDITOR')")                  → {@literal @}AuthCan(anyRole = "EDITOR")
 * </pre>
 *
 * <p>Se concede el acceso si pasa AL MENOS UNA comprobación (OR): habilidad {@code action}/{@code subject},
 * cualquiera de {@code anyAuthority} ({@code "action:subject"}), o cualquiera de {@code anyRole}. Todos los
 * miembros son {@link Nonbinding}: un solo interceptor cubre todas las combinaciones.</p>
 */
@InterceptorBinding
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface AuthCan {

    @Nonbinding String action() default "";

    @Nonbinding String subject() default "";

    @Nonbinding String[] anyAuthority() default {};

    @Nonbinding String[] anyRole() default {};
}
