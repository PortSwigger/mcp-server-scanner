package com.mcpscanner.access.mining;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecretNameTest {

    @Test
    void matchesPreSignedAndSignedLinkNames() {
        assertThat(SecretName.matches("presignedUrl")).isTrue();
        assertThat(SecretName.matches("signedPath")).isTrue();
        assertThat(SecretName.matches("signature")).isTrue();
    }

    @Test
    void doesNotMatchTheAuthorOfARecord() {
        assertThat(SecretName.matches("signed_by")).isFalse();
        assertThat(SecretName.matches("signedBy")).isFalse();
    }
}
