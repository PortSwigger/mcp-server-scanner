package com.mcpscanner.auth.oauth;

import com.mcpscanner.core.oauth.RegistrationMode;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;

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

    @Test
    void discoveryRequestsTheDiscoveredScopesTheUserDidNotDecline() {
        OAuthClientHints hints = selection(List.of("mcp:tools"), Set.of("mcp:resources", "mcp:prompts", "mcp:admin"), List.of());

        OAuthClientHints discovered = hints.withIssuer(ISSUER, ALL_SCOPES);

        assertThat(discovered.issuer()).isEqualTo(ISSUER);
        assertThat(discovered.scopes()).containsExactly("mcp:tools");
    }

    @Test
    void discoveryRequestsEveryAdvertisedScopeWhenTheTableIsEmpty() {
        assertThat(selection(List.of(), Set.of(), List.of()).withIssuer(ISSUER, ALL_SCOPES).scopes())
                .containsExactlyElementsOf(ALL_SCOPES);
    }

    @Test
    void discoveryRequestsNothingWhenEveryScopeIsDeclined() {
        assertThat(selection(List.of(), Set.copyOf(ALL_SCOPES), List.of()).withIssuer(ISSUER, ALL_SCOPES).scopes()).isEmpty();
    }

    @Test
    void aTickedCustomScopeIsAddedAfterTheDiscoveredScopes() {
        OAuthClientHints hints = selection(List.of("mcp:tools", "offline_access"), Set.of("mcp:admin"), List.of("offline_access"));

        assertThat(hints.withIssuer(ISSUER, ALL_SCOPES).scopes())
                .containsExactly("mcp:tools", "mcp:resources", "mcp:prompts", "offline_access");
    }

    @Test
    void discoveryKeepsTheScopeSelection() {
        OAuthClientHints hints = selection(List.of(), Set.of("mcp:admin"), List.of());

        assertThat(hints.withIssuer(ISSUER, ALL_SCOPES).scopeSelection()).isEqualTo(hints.scopeSelection());
    }

    @Test
    void aTickedDiscoveredScopeTheServerNoLongerAdvertisesIsNotRequested() {
        OAuthClientHints hints = selection(List.of("mcp:a"), Set.of(), List.of());

        assertThat(hints.withIssuer(ISSUER, List.of("mcp:b")).scopes()).containsExactly("mcp:b");
    }

    @Test
    void withoutDiscoveryEveryTickedScopeIsRequested() {
        assertThat(selection(List.of("mcp:a", "offline_access"), Set.of("mcp:b"), List.of("offline_access")).scopes())
                .containsExactly("mcp:a", "offline_access");
    }

    private static final List<String> ALL_SCOPES = List.of("mcp:tools", "mcp:resources", "mcp:prompts", "mcp:admin");

    private static OAuthClientHints selection(List<String> ticked, Set<String> declined, List<String> customTicked) {
        return new OAuthClientHints(null, ticked, null, null, true, 0, Duration.ofSeconds(120),
                RegistrationMode.AUTO, null, new ScopeSelection(declined, customTicked));
    }
}
