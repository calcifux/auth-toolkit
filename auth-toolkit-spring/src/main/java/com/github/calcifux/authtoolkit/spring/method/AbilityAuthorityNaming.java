package com.github.calcifux.authtoolkit.spring.method;

import com.github.calcifux.authtoolkit.Ability;

/**
 * Renders an {@link Ability} into the authority string that Spring Security's
 * {@code hasAuthority(...)} / {@code hasAnyAuthority(...)} check against. Default is
 * {@code action + ":" + subject} (e.g. {@code "publish:article"}). Override the bean to
 * emit your own naming (e.g. flat permission codes).
 */
@FunctionalInterface
public interface AbilityAuthorityNaming {

    String authority(Ability ability);

    /** {@code action:subject} — e.g. {@code "publish:article"}. */
    static AbilityAuthorityNaming defaultNaming() {
        return ability -> ability.action() + ":" + ability.subject();
    }
}
