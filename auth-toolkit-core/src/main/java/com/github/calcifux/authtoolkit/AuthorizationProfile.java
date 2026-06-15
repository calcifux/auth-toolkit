package com.github.calcifux.authtoolkit;

import java.util.List;
import java.util.Set;

/**
 * The authorization snapshot for a principal: the coarse {@code roles} (for display
 * and labels) and the flattened {@code abilities} the UI and the server actually
 * check. Produced by an {@link AbilityResolver} from LOCAL data and surfaced to the
 * client by the {@code /me} endpoint.
 *
 * @param roles     coarse role codes, e.g. {@code "LEADER"} (display only — do NOT gate on names)
 * @param abilities the flattened capability list the app authorizes against
 */
public record AuthorizationProfile(Set<String> roles, List<Ability> abilities) {

    public AuthorizationProfile {
        roles = (roles == null) ? Set.of() : Set.copyOf(roles);
        abilities = (abilities == null) ? List.of() : List.copyOf(abilities);
    }

    public static AuthorizationProfile empty() {
        return new AuthorizationProfile(Set.of(), List.of());
    }
}
