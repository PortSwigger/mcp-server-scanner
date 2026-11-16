package com.mcpscanner.integration;

import com.mcpscanner.access.comparison.CrossIdentityComparison;
import com.mcpscanner.access.comparison.CrossIdentityPorts;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.access.AccessComparison;
import com.mcpscanner.access.AccessComparisonRun;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessLedger;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.cvetargets.requests.VerbatimHeaderHttp;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.performance.RequestBudgets;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;
import java.util.Map;
import java.util.Optional;

class CheckAccessRequestBudgetTest {

    private static final Principal ALICE = signedIn(Principal.PRIMARY_ID, "alice", PrincipalRole.PRIMARY);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @ParameterizedTest(name = "{0} server, {1} credentials")
    @CsvSource({"stateless, same", "stateless, distinct", "stateful, same", "stateful, distinct"})
    void oneCheckAccessItemStaysWithinBudget(String server, String credentials) throws Exception {
        try (IdentityFixtureServer target = server.equals("stateful")
                ? IdentityFixtureServer.statefulSessions(true) : IdentityFixtureServer.statelessVersionScoped();
             ScannerProxyFixture proxy = ScannerProxyFixture.connect(target.endpoint(), TransportType.STREAMABLE_HTTP)) {
            Http http = proxy.routed(new VerbatimHeaderHttp());
            target.requests.clear();

            try (AccessComparisonRun run = comparison(compared(credentials)).begin(http)) {
                run.compare(ownerRequest(http, proxy));
            }

            RequestBudgets.assertWithin("Check access per item, " + server + " server, " + credentials
                    + " credentials", target.requests);
        }
    }

    @org.junit.jupiter.api.Test
    void oneCheckAccessItemRefusedAtTheCapturedVersionStaysWithinBudget() throws Exception {
        try (IdentityFixtureServer target = IdentityFixtureServer.statelessVersionScoped();
             ScannerProxyFixture proxy = ScannerProxyFixture.connect(target.endpoint(), TransportType.STREAMABLE_HTTP)) {
            Http http = proxy.routed(new VerbatimHeaderHttp());
            target.requests.clear();

            try (AccessComparisonRun run = comparison(signedIn("bob", "bob", PrincipalRole.PEER)).begin(http)) {
                run.compare(ownerRequest(http, proxy, "admin_report"));
            }

            RequestBudgets.assertWithin("Check access per item, stateless server, refused at the captured version",
                    target.requests);
        }
    }

    private static Principal compared(String credentials) {
        return credentials.equals("same")
                ? new Principal("user", "user", PrincipalRole.PEER, ALICE.credentialHeaders(), Optional.empty(), Map.of())
                : signedIn("bob", "bob", PrincipalRole.PEER);
    }

    private static AccessComparison comparison(Principal compared) {
        return new CrossIdentityComparison(McpEventLog.noop(), () -> new BearerTokenAuthStrategy("alice-token"),
                () -> PrincipalRoster.of(ALICE, List.of(compared)),
                CrossIdentityPorts.of(new AnySignedInLedger(), PrincipalListings.unknown()));
    }

    private static Principal signedIn(String id, String name, PrincipalRole role) {
        return new Principal(id, name, role, () -> Map.of("Authorization", "Bearer " + name + "-token"),
                Optional.empty(), Map.of());
    }

    private static HttpRequestResponse ownerRequest(Http http, ScannerProxyFixture proxy) {
        return ownerRequest(http, proxy, "read_session_record");
    }

    private static HttpRequestResponse ownerRequest(Http http, ScannerProxyFixture proxy, String tool) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(proxy.session().resolvedEndpoint()).withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withHeader("Accept", "application/json, text/event-stream");
        for (Map.Entry<String, String> header : proxy.baseHeaders().entrySet()) {
            request = request.withHeader(header.getKey(), header.getValue());
        }
        return http.sendRequest(request.withBody("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"" + tool + "\",\"arguments\":{}}}"));
    }

    private static final class AnySignedInLedger implements AccessLedger {

        @Override
        public AccessExpectation expectationFor(AccessItemKey item) {
            return AccessExpectation.ANY_SIGNED_IN;
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
