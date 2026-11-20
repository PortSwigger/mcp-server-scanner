package com.mcpscanner.checks.catalog.sessionlifecycle;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.AccessLedger;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ScriptedBurpHttp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

class SseSessionLifecycleTest {

    private final FakeSseSessionServer server = new FakeSseSessionServer();
    private final McpEventLog log = new McpEventLog(null);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void appliesToALegacySseMessageRequest() {
        assertThat(check().appliesTo(base())).isTrue();
    }

    @Test
    void pointerLikeSseSessionIdsAreReportedAsGuessable() {
        AtomicLong pointer = new AtomicLong(0x55d0c8a3b2c0L);
        server.ids = () -> "0x" + Long.toHexString(pointer.getAndAdd(0x1a0));

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("Guessable MCP session IDs");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
            assertThat(issue.detail()).contains("0x55d0c8a3b2c0");
            assertThat(issue.requestResponses()).isNotEmpty().allSatisfy(exchange ->
                    assertThat(exchange.request().url()).contains("session_id="));
        });
        assertThat(server.issued).hasSize(8);
        assertThat(server.closed).containsExactlyInAnyOrderElementsOf(server.issued);
        assertThat(messages()).anyMatch(message -> message.contains("stream closes"));
    }

    @Test
    void memoryAddressSessionIdsInTheMessagePathAreReportedAsGuessable() {
        AtomicLong pointer = new AtomicLong(281_470_279_102_720L);
        server.messageUrl = FakeSseSessionServer.PATH_MESSAGE_URL;
        server.ids = () -> Long.toString(pointer.getAndAdd(64L << 20));

        assertThat(audit(base(FakeSseSessionServer.PATH_MESSAGE_URL + "281470010667200")))
                .singleElement().satisfies(issue -> assertThat(issue.detail()).contains("281470279102720"));
        assertThat(server.closed).containsExactlyInAnyOrderElementsOf(server.issued);
    }

    @Test
    void pathSessionHandshakesAreAttachedWithTheIssuedIdHighlighted() {
        AtomicLong pointer = new AtomicLong(281_470_279_102_720L);
        server.messageUrl = FakeSseSessionServer.PATH_MESSAGE_URL;
        server.ids = () -> Long.toString(pointer.getAndAdd(64L << 20));

        assertThat(audit(base(FakeSseSessionServer.PATH_MESSAGE_URL + "281470010667200"))).singleElement()
                .satisfies(issue -> assertThat(issue.requestResponses()).hasSize(GuessabilityArm.SHOWN_HANDSHAKES)
                        .satisfiesExactly(
                                exchange -> assertHighlighted(exchange, server.issued.get(0)),
                                exchange -> assertHighlighted(exchange, server.issued.get(1))));
    }

    @Test
    void urlEncodedQuerySessionHandshakesAreAttachedWithTheEncodedIdHighlighted() {
        AtomicLong pointer = new AtomicLong(281_470_279_102_720L);
        server.encodeIds = true;
        server.ids = () -> "p+" + pointer.getAndAdd(64L << 20) + "==";

        assertThat(audit()).singleElement()
                .satisfies(issue -> assertThat(issue.requestResponses()).hasSize(GuessabilityArm.SHOWN_HANDSHAKES)
                        .satisfiesExactly(
                                exchange -> assertHighlighted(exchange, encoded(server.issued.get(0))),
                                exchange -> assertHighlighted(exchange, encoded(server.issued.get(1)))));
    }

    @Test
    void aSessionIdThatPrefixesAnotherDoesNotLabelItsHandshake() {
        java.util.Iterator<String> ids = List.of("1", "10", "20", "30", "40", "50", "60", "70").iterator();
        server.ids = ids::next;

        assertThat(audit()).singleElement()
                .satisfies(issue -> assertThat(issue.requestResponses()).hasSize(GuessabilityArm.SHOWN_HANDSHAKES)
                        .satisfiesExactly(
                                exchange -> assertHighlighted(exchange, "1"),
                                exchange -> assertHighlighted(exchange, "10")));
    }

    @Test
    void aPathOnlyRequestIsNotTreatedAsSseWhenTheTransportIsNotSse() {
        CheckServices services = new CheckServices(log, () -> () -> Map.of(), Optional::empty, Optional::empty,
                PrincipalRoster::empty, AccessLedger.noop(), PrincipalListings.unknown(), Optional::empty);
        HostCheck plain = (HostCheck) new SessionLifecycleCheckFactory().create(services);

        assertThat(plain.appliesTo(base(FakeSseSessionServer.PATH_MESSAGE_URL + "281470010667200"))).isFalse();
    }

    @Test
    void theSseFallbackMessageRouteIsNotASessionId() {
        server.messageUrl = "http://target.test/message";
        server.fixedRoute = true;
        server.ids = () -> UUID.randomUUID().toString();

        assertThat(audit(base("http://target.test/message"))).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("no session ID"));
        assertThat(server.closed).hasSameSizeAs(server.issued);
    }

    @Test
    void aFixedMessagePathWithoutASessionIsNotASessionId() {
        server.messageUrl = "http://target.test/mcp/messages";
        server.fixedRoute = true;
        server.ids = () -> UUID.randomUUID().toString();

        assertThat(audit(base("http://target.test/mcp/messages"))).isEmpty();
        assertThat(server.closed).hasSameSizeAs(server.issued);
    }

    @Test
    void everyProbeStreamClosesEvenWhenItsSessionIdRepeats() {
        java.util.Iterator<String> ids = List.of("281470279102720", "281470346211584", "281470279102720",
                "281470413320448", "281470346211584", "281470480429312", "281470547538176", "281470614647040",
                "281470681755904", "281470748864768").iterator();
        server.messageUrl = FakeSseSessionServer.PATH_MESSAGE_URL;
        server.ids = ids::next;

        assertThat(audit(base(FakeSseSessionServer.PATH_MESSAGE_URL + "281470010667200"))).singleElement()
                .satisfies(issue -> assertThat(issue.detail()).contains("same session ID"));
        assertThat(server.closed).hasSameSizeAs(server.issued);
    }

    @Test
    void randomSseSessionIdsStaySilentAndEveryStreamCloses() {
        server.ids = () -> UUID.randomUUID().toString();

        assertThat(audit()).isEmpty();
        assertThat(server.issued).hasSize(8);
        assertThat(server.closed).containsExactlyInAnyOrderElementsOf(server.issued);
    }

    @Test
    void theLiveSseSessionIsPingedAfterwardsAndNeverReplaced() {
        server.ids = () -> UUID.randomUUID().toString();

        audit();

        assertThat(server.issued).doesNotContain(FakeSseSessionServer.LIVE_SESSION);
        assertThat(server.posts.get(server.posts.size() - 1).uri().getQuery())
                .isEqualTo("session_id=" + FakeSseSessionServer.LIVE_SESSION);
        assertThat(messages()).anyMatch(message -> message.contains("still answers ping"));
    }

    @Test
    void theDeleteTestIsLoggedAsNotApplicableToLegacySse() {
        server.ids = () -> UUID.randomUUID().toString();

        audit();

        assertThat(messages()).contains("Scan check: session-lifecycle — skipped the DELETE test on "
                + base().request().url() + " (not applicable: a legacy SSE session ends when its stream closes)");
    }

    private List<AuditIssue> audit() {
        return audit(base());
    }

    private List<AuditIssue> audit(HttpRequestResponse base) {
        return check().audit(base, new ScriptedBurpHttp(server::respond));
    }

    private HostCheck check() {
        CheckServices services = new CheckServices(log, () -> () -> Map.of(), Optional::empty, Optional::empty,
                PrincipalRoster::empty, AccessLedger.noop(), PrincipalListings.unknown(), () -> Optional.of(server));
        return (HostCheck) new SessionLifecycleCheckFactory().create(services);
    }

    private static HttpRequestResponse base() {
        return base(FakeSseSessionServer.QUERY_MESSAGE_URL + FakeSseSessionServer.LIVE_SESSION);
    }

    private static HttpRequestResponse base(String url) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(url).withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\",\"params\":{}}");
        return HttpRequestResponse.httpRequestResponse(request,
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                        + "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[]}}"));
    }

    private static void assertHighlighted(HttpRequestResponse exchange, String text) {
        assertThat(exchange.request().url()).endsWith(text);
        String sent = exchange.request().toByteArray().toString();
        assertThat(exchange.requestMarkers()).isNotEmpty().allSatisfy(marker -> assertThat(
                sent.substring(marker.range().startIndexInclusive(), marker.range().endIndexExclusive()))
                .isEqualTo(text));
    }

    private static String encoded(String id) {
        return java.net.URLEncoder.encode(id, java.nio.charset.StandardCharsets.UTF_8);
    }

    private List<String> messages() {
        return log.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }
}
