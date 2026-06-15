package com.github.calcifux.authtoolkit;

import java.util.Map;

/**
 * A single capability the user may exercise, modeled CASL-style as
 * {@code (action, subject)} plus optional {@code conditions}.
 *
 * <p>Pure RBAC is the special case where {@code conditions} is empty (the ability is
 * unconditional). ABAC is added later by populating {@code conditions} (e.g.
 * {@code {"ownerId": "${userId}"}}) WITHOUT changing this shape or any call site —
 * that is the whole point of choosing the object form over a flat
 * {@code "subject.action"} string.</p>
 *
 * @param action     the verb, e.g. {@code "read"}, {@code "approve"}, {@code "export"}
 * @param subject    the resource type, e.g. {@code "workorder"}, {@code "file"}
 * @param conditions optional ABAC constraints; empty == unconditional (RBAC)
 */
public record Ability(String action, String subject, Map<String, Object> conditions) {

    public Ability {
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("Ability.action must not be blank");
        }
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("Ability.subject must not be blank");
        }
        conditions = (conditions == null) ? Map.of() : Map.copyOf(conditions);
    }

    /** Unconditional (RBAC) ability. */
    public static Ability of(String action, String subject) {
        return new Ability(action, subject, Map.of());
    }

    /** Conditional (ABAC) ability. */
    public static Ability of(String action, String subject, Map<String, Object> conditions) {
        return new Ability(action, subject, conditions);
    }

    /** {@code true} when this ability carries ABAC conditions. */
    public boolean isConditional() {
        return !conditions.isEmpty();
    }
}
