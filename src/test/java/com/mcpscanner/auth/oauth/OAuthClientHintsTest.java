package com.mcpscanner.auth.oauth;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthClientHintsTest {

    private static final URI ISSUER = URI.create("https://issuer.example");

    @Test
    void defaultPortIsZeroWhenNotSpecified() {
        OAuthClientHints hints = new OAuthClientHints(
                ISSUER, List.of(), "client-id", null, false, 0, Duration.ofSeconds(120));

        assertThat(hints.redirectPort()).isEqualTo(0);
    }

    @Test
    void portZeroIsNotRewrittenToHardCodedDefault() {
        OAuthClientHints hints = new OAuthClientHints(
                ISSUER, List.of(), "client-id", null, false, 0, Duration.ofSeconds(120));

        assertThat(hints.redirectPort()).isNotEqualTo(33418);
    }

    @Test
    void explicitPortIsPreserved() {
        OAuthClientHints hints = new OAuthClientHints(
                ISSUER, List.of(), "client-id", null, false, 12345, Duration.ofSeconds(120));

        assertThat(hints.redirectPort()).isEqualTo(12345);
    }

    @Test
    void negativePorts_areNotRewrittenToHardCodedDefault() {
        OAuthClientHints hints = new OAuthClientHints(
                ISSUER, List.of(), "client-id", null, false, -1, Duration.ofSeconds(120));

        assertThat(hints.redirectPort()).isEqualTo(-1);
    }
}
