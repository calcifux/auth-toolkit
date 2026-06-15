package com.github.calcifux.authtoolkit.spring.web;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Injects the current request's identity into a controller method parameter — the
 * "magic for devs", done the idiomatic Spring MVC way (a {@link CurrentUserArgumentResolver},
 * not arg-rewriting AOP). The injected value depends on the parameter TYPE:
 *
 * <pre>{@code
 * @GetMapping("/me")
 * Me me(@CurrentUser AuthPrincipal principal) { ... }      // the principal (or null)
 *
 * @PostMapping("/articles")
 * void create(@CurrentUser UUID userId) { ... }            // just the local user id
 *
 * void audit(@CurrentUser AuthorizationProfile profile) {} // roles + abilities
 * void maybe(@CurrentUser Optional<AuthPrincipal> who) {}  // explicit optionality
 * }</pre>
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
public @interface CurrentUser {

    /** When {@code true}, an anonymous request fails with 401 instead of injecting {@code null}/empty. */
    boolean required() default false;
}
