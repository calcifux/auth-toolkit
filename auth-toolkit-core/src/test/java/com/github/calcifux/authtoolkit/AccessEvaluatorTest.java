package com.github.calcifux.authtoolkit;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AccessEvaluatorTest {

    private final List<Ability> granted = List.of(
            Ability.of("read", "workorder"),
            Ability.of("approve", "workorder"));

    @Test
    void grantsMatchingUnconditionalAbility() {
        assertThat(AccessEvaluator.can(granted, "approve", "workorder")).isTrue();
        assertThat(AccessEvaluator.can(granted, "read", "workorder")).isTrue();
    }

    @Test
    void deniesUnknownActionOrSubject() {
        assertThat(AccessEvaluator.can(granted, "delete", "workorder")).isFalse();
        assertThat(AccessEvaluator.can(granted, "read", "budget")).isFalse();
    }

    @Test
    void wildcardAndManageMatchAnyAction() {
        List<Ability> admin = List.of(Ability.of(AccessEvaluator.MANAGE, "workorder"));
        assertThat(AccessEvaluator.can(admin, "delete", "workorder")).isTrue();

        List<Ability> superuser = List.of(Ability.of(AccessEvaluator.ANY, AccessEvaluator.ANY));
        assertThat(AccessEvaluator.can(superuser, "whatever", "anything")).isTrue();
    }

    @Test
    void failsClosedOnNullInput() {
        assertThat(AccessEvaluator.can(null, "read", "workorder")).isFalse();
        assertThat(AccessEvaluator.can(granted, null, "workorder")).isFalse();
        assertThat(AccessEvaluator.can(granted, "read", null)).isFalse();
    }

    @Test
    void conditionalAbilityDoesNotGrantWithoutResource() {
        List<Ability> owned = List.of(Ability.of("update", "workorder", Map.of("ownerId", "u1")));
        // RBAC overload (no resource) → conditional ability cannot grant: fail-closed.
        assertThat(AccessEvaluator.can(owned, "update", "workorder")).isFalse();
    }

    @Test
    void conditionalAbilityGrantsWhenConditionHolds() {
        List<Ability> owned = List.of(Ability.of("update", "workorder", Map.of("ownerId", "u1")));
        AccessEvaluator.ConditionEvaluator ownerCheck =
                (conditions, resource) -> resource.get("ownerId").equals(conditions.get("ownerId"));

        assertThat(AccessEvaluator.can(owned, "update", "workorder", Map.of("ownerId", "u1"), ownerCheck)).isTrue();
        assertThat(AccessEvaluator.can(owned, "update", "workorder", Map.of("ownerId", "u2"), ownerCheck)).isFalse();
    }
}
