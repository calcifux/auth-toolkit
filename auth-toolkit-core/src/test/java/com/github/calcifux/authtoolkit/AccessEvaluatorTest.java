package com.github.calcifux.authtoolkit;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AccessEvaluatorTest {

    private final List<Ability> granted = List.of(
            Ability.of("read", "article"),
            Ability.of("publish", "article"));

    @Test
    void grantsMatchingUnconditionalAbility() {
        assertThat(AccessEvaluator.can(granted, "publish", "article")).isTrue();
        assertThat(AccessEvaluator.can(granted, "read", "article")).isTrue();
    }

    @Test
    void deniesUnknownActionOrSubject() {
        assertThat(AccessEvaluator.can(granted, "delete", "article")).isFalse();
        assertThat(AccessEvaluator.can(granted, "read", "report")).isFalse();
    }

    @Test
    void wildcardAndManageMatchAnyAction() {
        List<Ability> admin = List.of(Ability.of(AccessEvaluator.MANAGE, "article"));
        assertThat(AccessEvaluator.can(admin, "delete", "article")).isTrue();

        List<Ability> superuser = List.of(Ability.of(AccessEvaluator.ANY, AccessEvaluator.ANY));
        assertThat(AccessEvaluator.can(superuser, "whatever", "anything")).isTrue();
    }

    @Test
    void failsClosedOnNullInput() {
        assertThat(AccessEvaluator.can(null, "read", "article")).isFalse();
        assertThat(AccessEvaluator.can(granted, null, "article")).isFalse();
        assertThat(AccessEvaluator.can(granted, "read", null)).isFalse();
    }

    @Test
    void conditionalAbilityDoesNotGrantWithoutResource() {
        List<Ability> owned = List.of(Ability.of("edit", "article", Map.of("authorId", "a1")));
        // RBAC overload (no resource) → conditional ability cannot grant: fail-closed.
        assertThat(AccessEvaluator.can(owned, "edit", "article")).isFalse();
    }

    @Test
    void conditionalAbilityGrantsWhenConditionHolds() {
        List<Ability> owned = List.of(Ability.of("edit", "article", Map.of("authorId", "a1")));
        AccessEvaluator.ConditionEvaluator ownerCheck =
                (conditions, resource) -> resource.get("authorId").equals(conditions.get("authorId"));

        assertThat(AccessEvaluator.can(owned, "edit", "article", Map.of("authorId", "a1"), ownerCheck)).isTrue();
        assertThat(AccessEvaluator.can(owned, "edit", "article", Map.of("authorId", "a2"), ownerCheck)).isFalse();
    }
}
