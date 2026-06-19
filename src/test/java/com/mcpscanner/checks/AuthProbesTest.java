package com.mcpscanner.checks;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

class AuthProbesTest {

    private static final String AUTHORIZATION = "Authorization";
    private static final String COOKIE = "Cookie";
    private static final String MCP_SESSION_ID = "Mcp-Session-Id";
    private static final String CUSTOM_AUTH_HEADER = "X-Api-Key";

    @Test
    void stripAuthRemovesAuthorizationCookieSessionAndContributedHeaders() {
        AuthStrategy customAuth = new CustomHeaderAuthStrategy(Map.of(CUSTOM_AUTH_HEADER, "abc"));

        AuthProbe probe = AuthProbes.stripAuth(customAuth);

        assertThat(caseInsensitive(probe.headersToRemove()))
                .contains(AUTHORIZATION, COOKIE, MCP_SESSION_ID, CUSTOM_AUTH_HEADER);
    }

    @Test
    void emptyBearerProbeStripsSessionAndAuthBearingHeaders() {
        AuthStrategy customAuth = new CustomHeaderAuthStrategy(Map.of(CUSTOM_AUTH_HEADER, "abc"));

        List<AuthProbe> probes = AuthProbes.invalidTokenProbes(customAuth);

        AuthProbe emptyBearer = probeByLabel(probes, "EMPTY_BEARER");
        assertThat(caseInsensitive(emptyBearer.headersToRemove()))
                .contains(AUTHORIZATION, COOKIE, MCP_SESSION_ID, CUSTOM_AUTH_HEADER);
        assertThat(emptyBearer.headersToOverride()).containsEntry(AUTHORIZATION, "Bearer ");
    }

    @Test
    void garbageBearerProbeStripsSessionAndAuthBearingHeaders() {
        AuthStrategy customAuth = new CustomHeaderAuthStrategy(Map.of(CUSTOM_AUTH_HEADER, "abc"));

        List<AuthProbe> probes = AuthProbes.invalidTokenProbes(customAuth);

        AuthProbe garbageBearer = probeByLabel(probes, "GARBAGE_BEARER");
        assertThat(caseInsensitive(garbageBearer.headersToRemove()))
                .contains(AUTHORIZATION, COOKIE, MCP_SESSION_ID, CUSTOM_AUTH_HEADER);
        assertThat(garbageBearer.headersToOverride()).containsKey(AUTHORIZATION);
    }

    @Test
    void noSchemeProbeStripsSessionAndAuthBearingHeaders() {
        AuthStrategy customAuth = new CustomHeaderAuthStrategy(Map.of(CUSTOM_AUTH_HEADER, "abc"));

        List<AuthProbe> probes = AuthProbes.invalidTokenProbes(customAuth);

        AuthProbe noScheme = probeByLabel(probes, "NO_SCHEME");
        assertThat(caseInsensitive(noScheme.headersToRemove()))
                .contains(AUTHORIZATION, COOKIE, MCP_SESSION_ID, CUSTOM_AUTH_HEADER);
        assertThat(noScheme.headersToOverride()).containsKey(AUTHORIZATION);
    }

    @Test
    void invalidTokenProbesWithoutContributedHeadersStillStripSessionAndCookie() {
        List<AuthProbe> probes = AuthProbes.invalidTokenProbes(new NoAuthStrategy());

        for (AuthProbe probe : probes) {
            assertThat(caseInsensitive(probe.headersToRemove()))
                    .as("probe %s should strip session/cookie/auth", probe.label())
                    .contains(AUTHORIZATION, COOKIE, MCP_SESSION_ID);
        }
    }

    @Test
    void invalidTokenProbesEnumeratesEmptyGarbageAndNoScheme() {
        List<AuthProbe> probes = AuthProbes.invalidTokenProbes(new NoAuthStrategy());

        assertThat(probes).extracting(AuthProbe::label)
                .containsExactly("EMPTY_BEARER", "GARBAGE_BEARER", "NO_SCHEME");
    }

    @Test
    void invalidTokenProbesReplaceCustomHeaderCredential() {
        AuthStrategy customAuth = new CustomHeaderAuthStrategy(Map.of(CUSTOM_AUTH_HEADER, "secret123"));

        List<AuthProbe> probes = AuthProbes.invalidTokenProbes(customAuth);

        AuthProbe emptyCustom = probeByLabel(probes, "EMPTY_X-API-KEY");
        assertThat(emptyCustom.headersToOverride()).containsEntry(CUSTOM_AUTH_HEADER, "");
        assertThat(emptyCustom.headersToOverride()).doesNotContainValue("secret123");

        AuthProbe garbageCustom = probeByLabel(probes, "GARBAGE_X-API-KEY");
        assertThat(garbageCustom.headersToOverride()).containsKey(CUSTOM_AUTH_HEADER);
        assertThat(garbageCustom.headersToOverride().get(CUSTOM_AUTH_HEADER))
                .isNotBlank()
                .isNotEqualTo("secret123");
        assertThat(garbageCustom.headersToOverride()).doesNotContainValue("secret123");

        assertThat(probes).extracting(AuthProbe::label)
                .doesNotContain("EMPTY_secret123", "GARBAGE_secret123");
    }

    @Test
    void stripAuth_addsStripSentinelToProbe() {
        AuthProbe probe = AuthProbes.stripAuth(new NoAuthStrategy());

        assertThat(probe.headersToOverride())
                .as("strip sentinel makes the proxy honour auth-stripping intent")
                .containsKey("X-Mcp-Scanner-Strip-Auth");
    }

    @Test
    void invalidTokenProbes_allIncludeStripSentinel() {
        AuthStrategy customAuth = new CustomHeaderAuthStrategy(Map.of(CUSTOM_AUTH_HEADER, "abc"));

        List<AuthProbe> probes = AuthProbes.invalidTokenProbes(customAuth);

        for (AuthProbe probe : probes) {
            assertThat(probe.headersToOverride())
                    .as("probe %s must instruct the proxy not to re-inject session auth", probe.label())
                    .containsKey("X-Mcp-Scanner-Strip-Auth");
        }
    }

    private Set<String> caseInsensitive(Set<String> values) {
        Set<String> set = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        set.addAll(values);
        return set;
    }

    private AuthProbe probeByLabel(List<AuthProbe> probes, String label) {
        return probes.stream()
                .filter(probe -> probe.label().equals(label))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Probe not found: " + label));
    }
}
