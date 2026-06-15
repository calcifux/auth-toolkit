package com.github.calcifux.authtoolkit;

import java.util.Collection;
import java.util.Map;

/**
 * Decides whether a set of granted {@link Ability}s permits an {@code (action, subject)}.
 * Fail-closed: anything unknown or null is denied.
 *
 * <p>Phase 1 (RBAC): an ability matches when its action+subject match (wildcards
 * {@code "*"} / {@code "manage"} allowed). Phase 2 (ABAC): pass a {@code resource}
 * map and a {@link ConditionEvaluator}; conditional abilities only grant when their
 * conditions hold against that resource. With no resource, conditional abilities are
 * treated as NOT granting (fail-closed) — the server must do the real check.</p>
 */
public final class AccessEvaluator {

    /** "manage" is the CASL-style super-action; "*" matches any action or subject. */
    public static final String MANAGE = "manage";
    public static final String ANY = "*";

    private AccessEvaluator() {
        // Utility class.
    }

    /** RBAC check: ignores conditions (a conditional ability does NOT grant here). */
    public static boolean can(Collection<Ability> granted, String action, String subject) {
        return can(granted, action, subject, null, null);
    }

    /**
     * Full check. When {@code resource}/{@code conditions} are provided, conditional
     * abilities are evaluated; otherwise only unconditional (RBAC) abilities can grant.
     *
     * @param granted   the principal's abilities (from {@link AuthorizationProfile})
     * @param action    the verb being attempted
     * @param subject   the resource type being acted on
     * @param resource  the concrete resource attributes for ABAC, or {@code null}
     * @param evaluator the condition evaluator for ABAC, or {@code null}
     */
    public static boolean can(
            Collection<Ability> granted,
            String action,
            String subject,
            Map<String, Object> resource,
            ConditionEvaluator evaluator) {
        if (granted == null || action == null || subject == null) {
            return false;
        }
        for (Ability ability : granted) {
            if (!subjectMatches(ability.subject(), subject) || !actionMatches(ability.action(), action)) {
                continue;
            }
            if (!ability.isConditional()) {
                return true; // unconditional grant
            }
            // Conditional (ABAC): only grants when we can evaluate it AND it holds.
            if (resource != null && evaluator != null && evaluator.matches(ability.conditions(), resource)) {
                return true;
            }
        }
        return false;
    }

    private static boolean actionMatches(String granted, String requested) {
        return ANY.equals(granted) || MANAGE.equals(granted) || granted.equalsIgnoreCase(requested);
    }

    private static boolean subjectMatches(String granted, String requested) {
        return ANY.equals(granted) || granted.equalsIgnoreCase(requested);
    }

    /** Pluggable ABAC condition check (e.g. a CASL-style MongoDB-query matcher). */
    @FunctionalInterface
    public interface ConditionEvaluator {
        boolean matches(Map<String, Object> conditions, Map<String, Object> resource);
    }
}
