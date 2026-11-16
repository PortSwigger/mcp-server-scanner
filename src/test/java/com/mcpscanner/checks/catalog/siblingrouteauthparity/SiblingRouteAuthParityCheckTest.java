package com.mcpscanner.checks.catalog.siblingrouteauthparity;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.HostAudits;
import com.mcpscanner.checks.issue.IssueRating;
import com.mcpscanner.checks.shared.auth.CatalogAccess;
import com.mcpscanner.checks.shared.probe.SimulatedMcpServer;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.mcpscanner.checks.shared.probe.SimulatedMcpServer.request;
import static com.mcpscanner.checks.shared.probe.SimulatedMcpServer.toolsList;
import static org.assertj.core.api.Assertions.assertThat;

class SiblingRouteAuthParityCheckTest {

    private static final Map<String, String> AUTHENTICATED =
            Map.of("Content-Type", "application/json", "Authorization", SimulatedMcpServer.VALID_TOKEN);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private static SiblingRouteAuthParityCheck check(Optional<HttpService> probeService) {
        return new SiblingRouteAuthParityCheck(McpEventLog.noop(), () -> new BearerTokenAuthStrategy("valid-token"), () -> probeService);
    }

    private static List<AuditIssue> audit(SimulatedMcpServer server, Optional<HttpService> probeService) {
        HttpRequestResponse base = server.exchange(request(toolsList(), AUTHENTICATED));
        return check(probeService).audit(base, server.http());
    }

    @Test
    void descriptorIsAHostCheckWithTheCatalogId() {
        assertThat(SiblingRouteAuthParityDescriptor.DESCRIPTOR.id()).isEqualTo("sibling-route-auth-parity");
        assertThat(SiblingRouteAuthParityDescriptor.DESCRIPTOR.kind()).isEqualTo(CheckKind.HOST);
        assertThat(check(Optional.empty()).descriptor()).isSameAs(SiblingRouteAuthParityDescriptor.DESCRIPTOR);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/messages", "/messages/", "/message", "/sse"})
    void reportsAKnownSiblingRouteThatAnswersWithoutCredentialsWhileTheMainRouteRefuses(String sibling) {
        List<AuditIssue> issues = audit(SimulatedMcpServer.enforcing().withUnguardedPath(sibling), Optional.empty());

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP sibling route lists the catalog without authentication");
            assertThat(new IssueRating(issue.severity(), issue.confidence()))
                    .isEqualTo(CatalogAccess.ALTERNATE_ROUTE.rating());
            assertThat(issue.detail()).contains(sibling).contains("/mcp").contains("tools/list");
            assertThat(issue.detail() + issue.definition().background()).doesNotContain("tools and data");
            assertThat(issue.requestResponses()).hasSizeGreaterThanOrEqualTo(3);
            assertThat(issue.requestResponses().get(0).request().headerValue("Authorization"))
                    .isEqualTo(SimulatedMcpServer.VALID_TOKEN);
        });
    }

    @ParameterizedTest
    @CsvSource({"/mcp_message,/mcp", "/mcp/,/mcp", "/mcp_message,/mcp?x=1", "/mcp/,/mcp?x=1"})
    void leavesToUnauthenticatedRequestExecutionACoveredRouteWhoseNonexistentChildControlIsRefused(
            String coveredRoute, String endpoint) {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath(coveredRoute);
        HttpRequestResponse base = server.exchange(request(toolsList(), AUTHENTICATED).withPath(endpoint));

        assertThat(check(Optional.empty()).audit(base, server.http())).isEmpty();
        assertThat(server.received()).extracting(HttpRequest::pathWithoutQuery).contains(coveredRoute)
                .anyMatch(path -> path.startsWith("/mcp/__mcp_"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/mcp_message", "/mcp/"})
    void reportsACoveredRouteWhenItsNonexistentChildControlIsNotRefused(String coveredRoute) {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath(coveredRoute)
                .answeringUnknownPathsWithAnAppPage();

        assertThat(audit(server, Optional.empty())).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP sibling route lists the catalog without authentication");
            assertThat(issue.detail()).contains(coveredRoute);
            assertThat(issue.requestResponses()).anyMatch(exchange ->
                    exchange.request().pathWithoutQuery().startsWith("/mcp/__mcp_"));
        });
    }

    @Test
    void triesTheRoutesUnauthenticatedRequestExecutionSweepsOnSseWhereThatCheckDoesNotRun() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/mcp_message");

        assertThat(audit(server, sseProxy())).singleElement().satisfies(issue ->
                assertThat(issue.name()).isEqualTo("MCP sibling route lists the catalog without authentication"));
    }

    @Test
    void opensAFreshAnonymousSessionOnASiblingThatRequiresOne() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().requiringSessions().withUnguardedPath("/messages/");
        Map<String, String> headers = new HashMap<>(AUTHENTICATED);
        headers.put("Mcp-Session-Id", server.openAuthenticatedSession());
        HttpRequestResponse base = server.exchange(request(toolsList(), headers));

        assertThat(check(Optional.empty()).audit(base, server.http())).singleElement()
                .satisfies(issue -> assertThat(issue.detail()).contains("/messages/"));
        assertThat(server.received()).anySatisfy(request -> {
            assertThat(request.pathWithoutQuery()).isEqualTo("/messages/");
            assertThat(request.bodyToString()).contains("\"initialize\"");
            assertThat(request.headerValue("Authorization")).isNull();
            assertThat(request.headerValue("Mcp-Session-Id")).isNull();
        });
        assertThat(server.received()).filteredOn(request -> request.pathWithoutQuery().equals("/messages/"))
                .allSatisfy(request -> assertThat(request.headerValue("Mcp-Session-Id"))
                        .isNotEqualTo(base.request().headerValue("Mcp-Session-Id")));
    }

    @Test
    void staysSilentWhenEverySiblingRouteRefusesTooAfterTryingThemAll() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing();

        assertThat(audit(server, Optional.empty())).isEmpty();
        assertThat(server.received()).extracting(HttpRequest::pathWithoutQuery)
                .contains("/mcp_message", "/mcp/", "/messages", "/messages/", "/message", "/sse");
        assertThat(server.received()).filteredOn(request -> !request.pathWithoutQuery().equals("/mcp"))
                .allSatisfy(request -> assertThat(request.headerValue("Authorization")).isNull());
    }

    @Test
    void staysSilentWhenASiblingRouteServesAnUnrelatedPublicCatalog() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().servingAnUnrelatedPublicCatalogOn("/messages");

        assertThat(audit(server, Optional.empty())).isEmpty();
        assertThat(server.received()).extracting(HttpRequest::pathWithoutQuery).contains("/messages");
    }

    @Test
    void staysSilentWhenTheProtectedCatalogIsEmpty() {
        assertThat(audit(SimulatedMcpServer.enforcing().listingNoTools().withUnguardedPath("/messages"),
                Optional.empty())).isEmpty();
    }

    @Test
    void leavesAServerThatAnswersAnonymouslyOnItsMainRouteToTheUnauthenticatedExecutionCheck() {
        SimulatedMcpServer server = SimulatedMcpServer.open().withUnguardedPath("/messages");

        assertThat(audit(server, Optional.empty())).isEmpty();
        assertThat(server.received()).extracting(HttpRequest::pathWithoutQuery).containsOnly("/mcp");
    }

    @Test
    void staysSilentWhenTheMainRouteStopsRefusingAfterTheSiblingAnswers() {
        SimulatedMcpServer server = SimulatedMcpServer.open().refusingTheFirstAnonymousRequests(2)
                .withUnguardedPath("/messages");

        assertThat(audit(server, Optional.empty())).isEmpty();
        assertThat(server.received()).extracting(HttpRequest::pathWithoutQuery).contains("/messages");
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "200 | text/html | <!doctype html><html><body>app</body></html>",
            "200 | application/json | {\"jsonrpc\":\"2.0\",\"id\":12,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}",
            "200 | application/json | {\"jsonrpc\":\"2.0\",\"id\":12,\"error\":{\"code\":-32602,\"message\":\"invalid\"}}",
            "202 | application/json | ''",
            "200 | application/json | {\"jsonrpc\":\"2.0\",\"id\":12,\"result\":{\"tools\":[]}}"
    })
    void staysSilentWhenASiblingAnswersWithSomethingOtherThanTheProtectedCatalog(int status, String contentType,
                                                                                String body) {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().answeringPath("/messages", status, contentType, body);

        assertThat(audit(server, Optional.empty())).isEmpty();
        assertThat(server.received()).extracting(HttpRequest::pathWithoutQuery).contains("/messages");
    }

    @Test
    void stopsAtTheRequestBudgetWithoutReportingARouteBeyondIt() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/sse");
        HttpRequestResponse base = server.exchange(request(toolsList(), AUTHENTICATED));

        assertThat(new SiblingRouteAuthParityCheck(McpEventLog.noop(), () -> new BearerTokenAuthStrategy("valid-token"),
                Optional::empty, 4).audit(base, server.http())).isEmpty();
        assertThat(server.received()).hasSize(1 + 4);
    }

    @Test
    void skipsTheRecheckAndStaysSilentWhenTheHitSpendsTheLastBudgetedRequest() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/messages");
        HttpRequestResponse base = server.exchange(request(toolsList(), AUTHENTICATED));

        assertThat(new SiblingRouteAuthParityCheck(McpEventLog.noop(), () -> new BearerTokenAuthStrategy("valid-token"),
                Optional::empty, 5).audit(base, server.http())).isEmpty();
        assertThat(server.received()).hasSize(1 + 5);
    }

    @Test
    void staysSilentWhenTheAuthenticatedBaselineFails() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/messages");
        HttpRequestResponse base = server.exchange(request(toolsList(), Map.of("Content-Type", "application/json")));

        assertThat(new SiblingRouteAuthParityCheck(McpEventLog.noop(), () -> new com.mcpscanner.auth.NoAuthStrategy(), Optional::empty)
                .audit(base, server.http())).isEmpty();
        assertThat(server.received()).hasSize(2);
    }

    @Test
    void reportsTheAdvertisedSseMessageRouteWhenItAcceptsMessagesWithoutCredentialsOnTheLiveStream() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().simulatingAProxyLiveStreamThatAcceptsAnonymousMessages();
        HttpRequestResponse base = server.exchange(request(toolsList(), AUTHENTICATED)
                .withPath("/mcp?sessionId=live-stream-session"));

        assertThat(check(sseProxy()).audit(base, server.http())).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP SSE message route lists the catalog without authentication");
            assertThat(new IssueRating(issue.severity(), issue.confidence()))
                    .isEqualTo(CatalogAccess.SESSION_CREDENTIAL.rating());
            assertThat(issue.definition().background()).doesNotContain("any network caller");
            assertThat(issue.detail()).startsWith("<p>The legacy SSE stream refused an anonymous client, but the "
                    + "message route it advertised, /mcp, accepted the request without credentials when it was "
                    + "posted with the session id of a stream the scanner had opened with credentials.")
                    .doesNotContain("live-stream-session");
        });
        assertThat(server.received()).filteredOn(request -> request.hasHeader(ScannerSentinels.KEEP_SESSION_HEADER))
                .allSatisfy(request -> {
                    assertThat(request.headerValue("Authorization")).isNull();
                    assertThat(request.hasHeader(ScannerSentinels.STRIP_AUTH_HEADER)).isTrue();
                });
    }

    @Test
    void neverPostsOnTheLiveSessionOfAStreamableServer() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().simulatingAProxyLiveStreamThatAcceptsAnonymousMessages();

        assertThat(audit(server, Optional.empty())).isEmpty();
        assertThat(server.received()).noneMatch(request -> request.hasHeader(ScannerSentinels.KEEP_SESSION_HEADER));
    }

    @Test
    void appliesOnlyToAJsonRpcCatalogListing() {
        SiblingRouteAuthParityCheck check = check(Optional.empty());

        assertThat(check.appliesTo(exchange(request(toolsList(), AUTHENTICATED)))).isTrue();
        assertThat(check.appliesTo(exchange(request(SimulatedMcpServer.toolCall(), AUTHENTICATED)))).isFalse();
        assertThat(check.appliesTo(exchange(request(SimulatedMcpServer.ping(), AUTHENTICATED)))).isFalse();
        assertThat(check.appliesTo(exchange(request(SimulatedMcpServer.notification(), AUTHENTICATED)))).isFalse();
        assertThat(check.appliesTo(exchange(request(toolsList(), AUTHENTICATED).withMethod("GET")))).isFalse();
    }

    private static Optional<HttpService> sseProxy() {
        return Optional.of(HttpService.httpService("127.0.0.1", 18080, false));
    }

    @Test
    void auditsTheFirstPageWhenTheCapturedListingCarriesACursorTheServerRejects() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().rejectingUnknownCursors().withUnguardedPath("/messages");
        HttpRequestResponse base = server.exchange(request(SimulatedMcpServer.toolsListPage("mcp-scanner-cursor"),
                AUTHENTICATED));

        assertThat(check(Optional.empty()).audit(base, server.http())).singleElement()
                .satisfies(issue -> assertThat(issue.detail()).contains("/messages"));
    }

    @Test
    void triesTheNextListingWhenTheFirstOneCarriesNoCatalogToCompare() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/messages");
        HttpRequestResponse emptyListing = server.exchange(request(RESOURCES_LIST, AUTHENTICATED));
        HttpRequestResponse toolsListing = server.exchange(request(toolsList(), AUTHENTICATED));
        HostAudits audits = new HostAudits(check(Optional.empty()));

        assertThat(audits.audit(emptyListing, server.http())).isEmpty();
        assertThat(audits.audit(toolsListing, server.http())).singleElement()
                .satisfies(issue -> assertThat(issue.detail()).contains("/messages"));
    }

    @Test
    void settlesOnTheFirstListingThatCarriesACatalog() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing();
        HostAudits audits = new HostAudits(check(Optional.empty()));

        audits.audit(server.exchange(request(toolsList(), AUTHENTICATED)), server.http());
        int sentForTheFirstListing = server.received().size();
        audits.audit(server.exchange(request(toolsList(), AUTHENTICATED)), server.http());

        assertThat(server.received()).hasSize(sentForTheFirstListing + 1);
    }

    private static final String RESOURCES_LIST = "{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"resources/list\",\"params\":{}}";

    private static HttpRequestResponse exchange(HttpRequest request) {
        return SimulatedMcpServer.enforcing().exchange(request);
    }
}
