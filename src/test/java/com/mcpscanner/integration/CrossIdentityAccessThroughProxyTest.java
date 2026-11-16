package com.mcpscanner.integration;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessLedger;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.access.AccessComparisonRun;
import com.mcpscanner.access.comparison.CrossIdentityComparison;
import com.mcpscanner.access.comparison.CrossIdentityPorts;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.cvetargets.requests.VerbatimHeaderHttp;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.mcpscanner.integration.IdentityToolCalls.base;
import static org.assertj.core.api.Assertions.assertThat;

class CrossIdentityAccessThroughProxyTest {

    private static final Principal ALICE = new Principal(Principal.PRIMARY_ID, "alice", PrincipalRole.PRIMARY,
            () -> Map.of("Authorization", "Bearer alice-token"), Optional.of(IdentityFixtureServer.MARKER), Map.of());
    private static final Principal BOB_LOWER = identity("bob", PrincipalRole.LOWER);

    private final McpEventLog eventLog = new McpEventLog(null);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private static Principal identity(String name, PrincipalRole role) {
        return new Principal(name, name, role, () -> Map.of("Authorization", "Bearer " + name + "-token"),
                Optional.empty(), Map.of());
    }

    @Test
    void lowerIdentityReachesAScopedToolAtTheLegacyVersionThroughTheProxy() throws Exception {
        try (IdentityFixtureServer server = IdentityFixtureServer.statelessVersionScoped();
             ScannerProxyFixture proxy = ScannerProxyFixture.connect(server.endpoint(), TransportType.STREAMABLE_HTTP)) {
            Http http = proxy.routed(new VerbatimHeaderHttp());

            List<AuditIssue> issues;
            try (AccessComparisonRun run = comparison(List.of(BOB_LOWER), AccessExpectation.NOT_LOWER).begin(http)) {
                issues = run.compare(base(http, proxy, "admin_report"));
            }

            assertThat(server.operations).contains("bob:admin_report@2024-11-05");
            assertThat(decisions()).contains("peer_replay:accepted_at_protocol_2024-11-05");
            assertThat(issues).singleElement().extracting(AuditIssue::name)
                    .isEqualTo("MCP operation available to a lower-privilege identity");
        }
    }

    @Test
    void identityNotExpectedToBeBlockedStillReportsAScopedToolReachedOnlyAtTheLegacyVersionThroughTheProxy()
            throws Exception {
        try (IdentityFixtureServer server = IdentityFixtureServer.statelessVersionScoped();
             ScannerProxyFixture proxy = ScannerProxyFixture.connect(server.endpoint(), TransportType.STREAMABLE_HTTP)) {
            Http http = proxy.routed(new VerbatimHeaderHttp());

            List<AuditIssue> issues;
            try (AccessComparisonRun run = comparison(List.of(identity("bob", PrincipalRole.PEER)),
                    AccessExpectation.ANY_SIGNED_IN).begin(http)) {
                issues = run.compare(base(http, proxy, "admin_report"));
            }

            assertThat(decisions()).contains("operation_level:refused_at_captured_protocol_version");
            assertThat(issues).singleElement().extracting(AuditIssue::name)
                    .isEqualTo("MCP operation available to a disallowed identity");
        }
    }

    private CrossIdentityComparison comparison(List<Principal> compared, AccessExpectation expectation) {
        return new CrossIdentityComparison(eventLog, () -> new BearerTokenAuthStrategy("alice-token"),
                () -> PrincipalRoster.of(ALICE, compared),
                CrossIdentityPorts.of(new FixedLedger(expectation), PrincipalListings.unknown()));
    }

    private List<String> decisions() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message)
                .map(message -> message.substring(message.lastIndexOf(": ") + 2)).toList();
    }

    private record FixedLedger(AccessExpectation expectation) implements AccessLedger {

        @Override
        public AccessExpectation expectationFor(AccessItemKey item) {
            return expectation;
        }

        @Override
        public void record(AccessItemKey item, String principalId, AccessOutcome outcome) {
        }

        @Override
        public void recordAnonymous(AccessItemKey item, AccessOutcome outcome) {
        }

        @Override
        public boolean permitsReplay(AccessItemKey item) {
            return true;
        }
    }
}
