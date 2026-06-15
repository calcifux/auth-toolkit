package com.github.calcifux.authtoolkit.spring.method;

import com.github.calcifux.authtoolkit.Ability;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AbilityAuthorityNamingTest {

    @Test
    void defaultNamingIsActionColonSubject() {
        AbilityAuthorityNaming naming = AbilityAuthorityNaming.defaultNaming();
        assertThat(naming.authority(Ability.of("publish", "article"))).isEqualTo("publish:article");
        assertThat(naming.authority(Ability.of("manage", "report"))).isEqualTo("manage:report");
    }
}
