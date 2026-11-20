package com.mcpscanner.identity;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AnonymousComparisonTest {

    @Test
    void namesNoCredentialAndTheFakeTokenAfterTheComparedUsers() {
        assertThat(AnonymousComparison.alongside("bob, carol")).isEqualTo("bob, carol + No credential + Fake token");
    }
}
