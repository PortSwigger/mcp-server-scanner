package com.mcpscanner.auth.oauth.safety;

import com.mcpscanner.auth.oauth.OAuthUrlValidator;
import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultSuspiciousDestinationGateTest {

    private static final URI MCP_ENDPOINT = URI.create("https://mcp.example.com/mcp");

    @Test
    void cleanHttpsHostAllowsWithoutPromptingTheConfirmer() throws Exception {
        StubHostResolver resolver = StubHostResolver.of("mcp.example.com", "203.0.113.10");
        RecordingConfirmer confirmer = new RecordingConfirmer(true);
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), resolver, confirmer, null);

        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                URI.create("https://mcp.example.com/.well-known/oauth-authorization-server"),
                FetchPurpose.of("AS metadata", MCP_ENDPOINT));

        assertThat(decision.isAllowed()).isTrue();
        assertThat(confirmer.calls()).isZero();
    }

    @Test
    void alwaysAllowConfirmerYieldsAllowDecision() throws Exception {
        StubHostResolver resolver = StubHostResolver.of("internal.corp", "10.0.0.5");
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), resolver,
                SuspiciousDestinationConfirmer.alwaysAllow(), null);

        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                URI.create("https://internal.corp/auth"),
                FetchPurpose.of("AS metadata", MCP_ENDPOINT));

        assertThat(decision.isAllowed()).isTrue();
    }

    @Test
    void alwaysDenyConfirmerYieldsDenyWithReason() throws Exception {
        StubHostResolver resolver = StubHostResolver.of("internal.corp", "10.0.0.5");
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), resolver,
                SuspiciousDestinationConfirmer.alwaysDeny(), null);

        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                URI.create("https://internal.corp/auth"),
                FetchPurpose.of("AS metadata", MCP_ENDPOINT));

        assertThat(decision.isDenied()).isTrue();
        assertThat(decision.reason()).isNotNull();
        assertThat(decision.reason().classifications())
                .contains(OAuthUrlValidator.CLASSIFICATION_PRIVATE);
        assertThat(decision.reason().resolvedAddress()).isEqualTo("10.0.0.5");
    }

    @Test
    void confirmerDeniesReturnsDenyWithReason() throws Exception {
        StubHostResolver resolver = StubHostResolver.of("internal.corp", "10.0.0.5");
        RecordingConfirmer confirmer = new RecordingConfirmer(false);
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), resolver, confirmer, null);

        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                URI.create("https://internal.corp/auth"),
                FetchPurpose.of("AS metadata", MCP_ENDPOINT));

        assertThat(decision.isDenied()).isTrue();
        assertThat(confirmer.calls()).isEqualTo(1);
        assertThat(confirmer.lastReason.classifications())
                .contains(OAuthUrlValidator.CLASSIFICATION_PRIVATE);
    }

    @Test
    void dnsTimeoutReturnsUnresolvableHardDenyWithoutPrompting() {
        HostResolver timingOutResolver = host -> {
            throw new HostResolver.ResolutionTimeoutException("timed out");
        };
        RecordingConfirmer confirmer = new RecordingConfirmer(true);
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), timingOutResolver, confirmer, null);

        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                URI.create("https://slow.example.com/auth"),
                FetchPurpose.of("AS metadata", MCP_ENDPOINT));

        assertThat(decision.isDenied()).isTrue();
        assertThat(decision.reason().classifications())
                .contains(OAuthUrlValidator.CLASSIFICATION_UNRESOLVABLE);
        assertThat(confirmer.calls()).isZero();
    }

    @Test
    void hardBlockClassificationsNeverPromptAndAlwaysDeny() {
        RecordingConfirmer confirmer = new RecordingConfirmer(true);
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), StubHostResolver.empty(), confirmer, null);

        SuspiciousDestinationGate.Decision javascriptScheme = gate.evaluate(
                URI.create("javascript:alert(1)"),
                FetchPurpose.of("AS metadata", MCP_ENDPOINT));
        SuspiciousDestinationGate.Decision missingHost = gate.evaluate(
                URI.create("https:///path"),
                FetchPurpose.of("AS metadata", MCP_ENDPOINT));

        assertThat(javascriptScheme.isDenied()).isTrue();
        assertThat(missingHost.isDenied()).isTrue();
        assertThat(confirmer.calls()).isZero();
    }

    @Test
    void crossOriginHostTriggersPromptEvenWhenPublicAddress() throws Exception {
        StubHostResolver resolver = StubHostResolver.of("auth.other.com", "203.0.113.20");
        RecordingConfirmer confirmer = new RecordingConfirmer(false);
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), resolver, confirmer, null);

        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                URI.create("https://auth.other.com/authorize"),
                FetchPurpose.of("Authorization endpoint", MCP_ENDPOINT));

        assertThat(decision.isDenied()).isTrue();
        assertThat(confirmer.lastReason.classifications())
                .contains(OAuthUrlValidator.CLASSIFICATION_CROSS_ORIGIN);
    }

    @Test
    void cacheReturnsSameDecisionAcrossInvocationsForSameUrl() throws Exception {
        StubHostResolver resolver = StubHostResolver.of("internal.corp", "10.0.0.5");
        RecordingConfirmer confirmer = new RecordingConfirmer(false);
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), resolver, confirmer, null);
        URI url = URI.create("https://internal.corp/auth");
        FetchPurpose purpose = FetchPurpose.of("AS metadata", MCP_ENDPOINT);

        SuspiciousDestinationGate.Decision first = gate.evaluate(url, purpose);
        SuspiciousDestinationGate.Decision second = gate.evaluate(url, purpose);

        assertThat(first.isDenied()).isTrue();
        assertThat(second.isDenied()).isTrue();
        assertThat(confirmer.calls()).isEqualTo(1);
    }

    @Test
    void resetClearsCacheSoSubsequentEvaluationsConsultConfirmerAgain() throws Exception {
        StubHostResolver resolver = StubHostResolver.of("internal.corp", "10.0.0.5");
        RecordingConfirmer confirmer = new RecordingConfirmer(false);
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), resolver, confirmer, null);
        URI url = URI.create("https://internal.corp/auth");
        FetchPurpose purpose = FetchPurpose.of("AS metadata", MCP_ENDPOINT);

        gate.evaluate(url, purpose);
        gate.reset();
        gate.evaluate(url, purpose);

        assertThat(confirmer.calls()).isEqualTo(2);
    }

    @Test
    void emitsEventLogLineWhenDecisionInvolvesClassification() throws Exception {
        StubHostResolver resolver = StubHostResolver.of("internal.corp", "10.0.0.5");
        McpEventLog log = new McpEventLog(null);
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), resolver,
                SuspiciousDestinationConfirmer.alwaysDeny(), log);

        gate.evaluate(URI.create("https://internal.corp/auth"),
                FetchPurpose.of("AS metadata", MCP_ENDPOINT));

        assertThat(log.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("OAuth destination denied")
                        && entry.message().contains("AS metadata")
                        && entry.message().contains(OAuthUrlValidator.CLASSIFICATION_PRIVATE));
    }

    @Test
    void plainHttpFires_promptShown_acceptProceeds() {
        StubHostResolver resolver = StubHostResolver.of("example.com", "203.0.113.5");
        RecordingConfirmer confirmer = new RecordingConfirmer(true);
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), resolver, confirmer, null);

        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                URI.create("http://example.com/.well-known/oauth-authorization-server"),
                FetchPurpose.of("AS metadata", MCP_ENDPOINT));

        assertThat(decision.isAllowed()).isTrue();
        assertThat(confirmer.calls()).isEqualTo(1);
        assertThat(confirmer.lastReason.classifications())
                .contains(OAuthUrlValidator.CLASSIFICATION_PLAIN_HTTP_NON_LOOPBACK);
    }

    @Test
    void plainHttpFires_confirmerDenies_returnsDeny() {
        StubHostResolver resolver = StubHostResolver.of("example.com", "203.0.113.5");
        RecordingConfirmer confirmer = new RecordingConfirmer(false);
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), resolver, confirmer, null);

        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                URI.create("http://example.com/.well-known/oauth-authorization-server"),
                FetchPurpose.of("AS metadata", MCP_ENDPOINT));

        assertThat(decision.isDenied()).isTrue();
        assertThat(decision.reason()).isNotNull();
        assertThat(decision.reason().classifications())
                .contains(OAuthUrlValidator.CLASSIFICATION_PLAIN_HTTP_NON_LOOPBACK);
    }

    @Test
    void confirmerThrowingTreatedAsDeny() {
        StubHostResolver resolver = StubHostResolver.of("internal.corp", "10.0.0.5");
        SuspiciousDestinationConfirmer boomConfirmer = reason -> {
            throw new IllegalStateException("boom");
        };
        DefaultSuspiciousDestinationGate gate = new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), resolver, boomConfirmer, null);

        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                URI.create("https://internal.corp/auth"),
                FetchPurpose.of("AS metadata", MCP_ENDPOINT));

        assertThat(decision.isDenied()).isTrue();
    }

    private static final class RecordingConfirmer implements SuspiciousDestinationConfirmer {
        private final boolean response;
        private final AtomicInteger callCount = new AtomicInteger();
        volatile SuspiciousDestinationGate.Reason lastReason;

        RecordingConfirmer(boolean response) {
            this.response = response;
        }

        int calls() {
            return callCount.get();
        }

        @Override
        public boolean confirm(SuspiciousDestinationGate.Reason reason) {
            callCount.incrementAndGet();
            lastReason = reason;
            return response;
        }
    }

    private static final class StubHostResolver implements HostResolver {
        private final Map<String, List<InetAddress>> fixture;

        StubHostResolver(Map<String, List<InetAddress>> fixture) {
            this.fixture = fixture;
        }

        static StubHostResolver of(String host, String address) {
            try {
                return new StubHostResolver(Map.of(host,
                        List.of(InetAddress.getByAddress(host, parseIpv4(address)))));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        static StubHostResolver empty() {
            return new StubHostResolver(Map.of());
        }

        @Override
        public List<InetAddress> resolve(String host) {
            return fixture.getOrDefault(host, List.of());
        }

        private static byte[] parseIpv4(String address) {
            String[] parts = address.split("\\.");
            byte[] bytes = new byte[4];
            for (int i = 0; i < 4; i++) {
                bytes[i] = (byte) Integer.parseInt(parts[i]);
            }
            return bytes;
        }
    }
}
