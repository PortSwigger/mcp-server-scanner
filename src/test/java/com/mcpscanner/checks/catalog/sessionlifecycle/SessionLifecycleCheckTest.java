package com.mcpscanner.checks.catalog.sessionlifecycle;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.AccessLedger;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.FakeMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ScriptedBurpHttp;
import com.mcpscanner.testutil.SendOnlyBurpHttp;
import burp.api.montoya.http.RequestOptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class SessionLifecycleCheckTest {

    private static final String ENDPOINT = "http://target.test/mcp";
    private static final String PREFIX = "Scan check: session-lifecycle — ";
    private static final String BASE_SUBJECT = "tools/list at " + ENDPOINT;

    private final FakeSessionServer server = new FakeSessionServer();
    private final McpEventLog log = new McpEventLog(null);
    private AuthStrategy auth = () -> Map.of("Authorization", FakeSessionServer.TOKEN);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void appliesOnlyToAnsweredRequestsCarryingASessionId() {
        assertThat(check().appliesTo(base())).isTrue();
        assertThat(check().appliesTo(HttpRequestResponse.httpRequestResponse(
                base().request().withRemovedHeader("Mcp-Session-Id"), base().response()))).isFalse();
        assertThat(check().appliesTo(HttpRequestResponse.httpRequestResponse(base().request(), null))).isFalse();
    }

    @Test
    void randomIdsAndAnHonouredDeleteStaySilentAndCleanUp() {
        assertThat(audit()).isEmpty();

        assertThat(server.issued).hasSize(8);
        assertThat(server.deleted).containsExactlyInAnyOrderElementsOf(server.issued);
        assertThat(server.received).noneMatch(request -> request.method().equals("DELETE")
                && FakeSessionServer.LIVE_SESSION.equals(FakeSessionServer.header(request, "Mcp-Session-Id")));
        assertThat(lastLiveSessionRequest().body()).contains("\"ping\"");
    }

    @Test
    void sequentialIdsAreReportedAsLowSeverity() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("Guessable MCP session IDs");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
            assertThat(issue.detail()).contains("session-000001").contains("increase");
        });
        assertThat(server.deleted).containsExactlyInAnyOrderElementsOf(server.issued);
    }

    @Test
    void guessableIdEvidenceIsTwoConsecutiveHandshakesWithTheIssuedIdsHighlighted() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.requestResponses()).hasSize(2);
            assertThat(issue.requestResponses()).extracting(SessionLifecycleCheckTest::highlightedResponseText)
                    .containsExactly("session-000001", "session-000002");
        });
    }

    @Test
    void bareUseEvidenceIsTheHandshakesThenTheAnonymousInitializeTheUnissuedIdAndTheSessionOnlyPing() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.requiresToken = true;
        server.sessionIsCredential = true;

        assertThat(audit()).singleElement().satisfies(issue -> {
            List<HttpRequestResponse> evidence = issue.requestResponses();
            assertThat(evidence).hasSize(5);
            assertThat(evidence.get(2).request().bodyToString()).contains("\"initialize\"");
            assertThat(evidence.get(2).request().hasHeader("Authorization")).isFalse();
            assertThat(server.neverIssued(sessionIdOf(evidence.get(3)))).isTrue();
            assertThat(server.issued).contains(sessionIdOf(evidence.get(4)));
            assertThat(evidence.get(4).request().hasHeader("Authorization")).isFalse();
            assertThat(evidence.get(4).response().statusCode()).isEqualTo((short) 200);
            assertThat(issue.detail()).contains("same ping without a session ID was refused");
        });
    }

    @Test
    void deletedReuseEvidenceIsTheUnissuedIdRefusalTheDeleteThePingAfterAndTheStreamPair() {
        server.deleteIgnored = true;

        assertThat(audit()).singleElement().satisfies(issue -> {
            List<HttpRequestResponse> evidence = issue.requestResponses();
            assertThat(evidence).extracting(exchange -> exchange.request().method())
                    .containsExactly("POST", "DELETE", "POST", "GET", "GET");
            assertThat(server.neverIssued(sessionIdOf(evidence.get(0)))).isTrue();
            assertThat(server.neverIssued(sessionIdOf(evidence.get(4)))).isTrue();
            assertThat(issue.detail()).doesNotContain("confirmed it answered ping");
        });
    }

    private static String sessionIdOf(HttpRequestResponse exchange) {
        return exchange.request().headers().stream().filter(header -> header.name().equalsIgnoreCase("Mcp-Session-Id"))
                .map(header -> header.value()).findFirst().orElse(null);
    }

    private static String highlightedResponseText(HttpRequestResponse exchange) {
        var range = exchange.responseMarkers().get(0).range();
        return exchange.response().toByteArray().toString().substring(range.startIndexInclusive(), range.endIndexExclusive());
    }

    @Test
    void guessableIdsThatAuthenticateWithoutCredentialsAreHighSeverity() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.requiresToken = true;
        server.sessionIsCredential = true;

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.detail()).contains("without credentials");
        });
    }

    @Test
    void guessableIdsStayLowWhenTheBareIdIsRefused() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.requiresToken = true;

        assertThat(audit()).singleElement()
                .satisfies(issue -> assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW));
    }

    @Test
    void aSessionThatAnswersAfterDeleteIsReported() {
        server.deleteIgnored = true;

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP session usable after DELETE");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.requestResponses()).extracting(exchange -> exchange.request().method())
                    .containsSubsequence("POST", "DELETE", "POST");
        });
    }

    @Test
    void aDeletedSessionWhoseEventStreamStillOpensIsReported() {
        server.deletedStreamsOpen = true;

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP session usable after DELETE");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
            assertThat(issue.detail()).contains("event stream");
            assertThat(issue.requestResponses()).extracting(exchange -> exchange.request().method())
                    .containsSubsequence("DELETE", "GET", "GET");
        });
        String deletedId = server.issued.get(0);
        assertThat(server.streamRequests).anySatisfy(get -> assertThat(get.headerValue("Mcp-Session-Id"))
                .isEqualTo(deletedId));
        assertThat(server.streamRequests).allSatisfy(get -> {
            assertThat(get.method()).isEqualTo("GET");
            assertThat(get.headerValue("Accept")).isEqualTo("text/event-stream");
            assertThat(get.headerValue("Authorization")).isEqualTo(FakeSessionServer.TOKEN);
        });
    }

    @Test
    void aStreamThatOpensForAnyIdIsNotReportedAsUsableAfterDelete() {
        server.streamsOpenForAnyId = true;

        assertThat(audit()).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("never-issued"));
    }

    @Test
    void aServerWithoutGetStreamsStaysSilentAfterAnHonouredDelete() {
        server.streamRefusalStatus = 405;

        assertThat(audit()).isEmpty();
        assertThat(server.streamRequests).isNotEmpty();
    }

    @Test
    void aDeletedSessionAnsweringBothPingAndStreamCarriesBothAsEvidence() {
        server.deleteIgnored = true;

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.detail()).contains("ping").contains("event stream");
            assertThat(issue.requestResponses()).extracting(exchange -> exchange.request().method())
                    .containsSubsequence("DELETE", "POST", "GET", "GET");
        });
    }

    @Test
    void deleteRejectedWithMethodNotAllowedSkipsTheDeleteArm() {
        server.deleteStatus = 405;

        assertThat(audit()).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("405"));
    }

    @Test
    void aServerThatRefusesASecondSessionIsSkipped() {
        server.sessionLimit = 1;

        assertThat(audit()).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("second"));
        assertThat(server.deleted).containsExactlyElementsOf(server.issued);
    }

    @Test
    void clearlyRandomIdsNeedOnlyEightProbeSessions() {
        audit();

        assertThat(server.issued).hasSize(8);
    }

    @Test
    void borderlineIdsOpenUpToThirtyProbeSessionsBeforeDeciding() {
        java.util.Iterator<String> ids = sixtyThreeBitIdsVaryingEveryBitInTheFirstEight().iterator();
        server.ids = ids::next;

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("Guessable MCP session IDs");
            assertThat(issue.detail()).contains("bits");
        });
        assertThat(server.issued).hasSize(30);
        assertThat(server.deleted).containsExactlyInAnyOrderElementsOf(server.issued);
        assertThat(messages()).anyMatch(message -> message.contains("borderline"));
    }

    @Test
    void sixtyFourBitIdsStaySilentAfterAtMostThirtyProbeSessions() {
        java.security.SecureRandom random = new java.security.SecureRandom();
        server.ids = () -> String.format("%016x", random.nextLong());

        assertThat(audit()).isEmpty();
        assertThat(server.issued).hasSizeLessThanOrEqualTo(30);
    }

    @Test
    void mongoObjectIdsAreReportedAsGuessable() {
        AtomicInteger counter = new AtomicInteger(0x41f2a0);
        byte[] process = {0x1a, 0x2b, 0x3c, 0x4d, 0x5e};
        server.ids = () -> com.mcpscanner.checks.catalog.sessionlifecycle.ids.IdFixtures.objectId(
                java.time.Instant.now(), process, counter.incrementAndGet());

        assertThat(audit()).singleElement().satisfies(issue -> assertThat(issue.detail())
                .contains("MongoDB ObjectId").contains("time the session was issued"));
    }

    @Test
    void aProbeIssuedTheLiveSessionIdNeverDeletesTheLiveSession() {
        server.ids = () -> FakeSessionServer.LIVE_SESSION;

        assertThat(audit()).extracting(AuditIssue::name).containsExactly("Guessable MCP session IDs");
        assertThat(server.deletesOf(FakeSessionServer.LIVE_SESSION)).isZero();
    }

    @Test
    void aRepeatedProbeIdIsDeletedOnlyOnce() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> counter.incrementAndGet() <= 2 ? "repeated-" + "a".repeat(32) : UUID.randomUUID().toString();

        audit();

        assertThat(server.deletesOf("repeated-" + "a".repeat(32))).isEqualTo(1);
    }

    @Test
    void aServerThatAcceptsAnySessionIdIsNotReportedAsUsableAfterDelete() {
        server.acceptsAnySession = true;

        assertThat(audit()).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("does not enforce"));
    }

    @Test
    void guessableIdsStayLowWhenAnySessionHeaderAuthenticates() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.requiresToken = true;
        server.sessionIsCredential = true;
        server.acceptsAnySession = true;

        assertThat(audit()).singleElement()
                .satisfies(issue -> assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW));
    }

    @Test
    void aDeleteWithoutAResponseKeepsTheOtherArmsFindings() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());

        List<AuditIssue> issues = check().audit(base(), droppingDeletes(new ScriptedBurpHttp(server::respond)));

        assertThat(issues).extracting(AuditIssue::name).containsExactly("Guessable MCP session IDs");
        assertThat(messages()).anyMatch(message -> message.contains("no response"));
    }

    @Test
    void theHighFindingNamesTheOverlappingUnauthenticatedRequestCheck() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.requiresToken = true;
        server.sessionIsCredential = true;

        assertThat(audit()).singleElement()
                .satisfies(issue -> assertThat(issue.detail()).contains("MCP session id accepted as credential"));
    }

    @Test
    void aDeletedSessionAnswered202WithoutAResultIsNotReported() {
        server.deletedSessionsAccepted = true;

        assertThat(audit()).isEmpty();
    }

    @Test
    void aBareIdThatGets200WithAJsonRpcErrorStaysLow() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.requiresToken = true;
        server.bareSessionsAnswerWithErrors = true;

        assertThat(audit()).singleElement()
                .satisfies(issue -> assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW));
    }

    @Test
    void aFreshProbeSessionThatDoesNotAnswerPingSkipsTheDeleteArm() {
        server.probeOperationsFail = true;
        server.deleteIgnored = true;

        assertThat(audit()).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("did not answer ping"));
    }

    @Test
    void aServerThatIssuesNoSessionIdToProbesIsSkipped() {
        server.ids = () -> null;

        assertThat(audit()).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("issued no session ID"));
    }

    @Test
    void aBaseRequestOnALiveSseMessageEndpointIsSkippedWithoutProbing() {
        HttpRequestResponse sse = HttpRequestResponse.httpRequestResponse(
                base().request().withPath("/messages/?session_id=live"), base().response());

        assertThat(check().audit(sse, new ScriptedBurpHttp(server::respond))).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("cannot be opened"));
        assertThat(server.issued).isEmpty();
    }

    @Test
    void aLiveSessionThatStopsAnsweringIsWarnedAbout() {
        server.endLiveSession();

        audit();

        assertThat(log.snapshot()).anySatisfy(entry -> {
            assertThat(entry.level()).isEqualTo(McpEventLog.Level.WARN);
            assertThat(entry.message()).contains("live session did not answer ping");
        });
    }

    @Test
    void aProbeHandshakeThatFailsAfterIssuingTheLiveIdNeverDeletesTheLiveSession() {
        server.ids = () -> FakeSessionServer.LIVE_SESSION;
        server.initializedStatus = 400;

        audit();

        assertThat(server.deletesOf(FakeSessionServer.LIVE_SESSION)).isZero();
    }

    @Test
    void aThrottledNeverIssuedIdControlDoesNotEstablishEnforcement() {
        server.acceptsAnySession = true;
        server.unissuedIdStatus = 429;

        assertThat(audit()).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("rate limited"));
    }

    @Test
    void aFailingNeverIssuedIdControlWithoutCredentialsKeepsGuessableIdsLow() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.requiresToken = true;
        server.sessionIsCredential = true;
        server.acceptsAnySession = true;
        server.unissuedIdStatus = 503;

        assertThat(audit()).singleElement()
                .satisfies(issue -> assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW));
    }

    @Test
    void bothFindingsCarryTheNeverIssuedIdRefusalAsEvidence() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.requiresToken = true;
        server.sessionIsCredential = true;
        server.deleteIgnored = true;

        assertThat(audit()).hasSize(2).allSatisfy(issue -> assertThat(issue.requestResponses())
                .anySatisfy(exchange -> assertThat(server.neverIssued(exchange.request().headerValue("MCP-Session-Id")))
                        .isTrue()));
    }

    @Test
    void aLivePingThatThrowsKeepsTheFindings() {
        server.deleteIgnored = true;
        ScriptedBurpHttp scripted = new ScriptedBurpHttp(server::respond);
        SendOnlyBurpHttp failingLivePing = new SendOnlyBurpHttp() {
            @Override
            public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions options) {
                if (FakeSessionServer.LIVE_SESSION.equals(request.headerValue("Mcp-Session-Id"))) {
                    throw new IllegalStateException("connection reset");
                }
                return scripted.sendRequest(request, options);
            }
        };

        assertThat(check().audit(base(), failingLivePing)).extracting(AuditIssue::name)
                .containsExactly("MCP session usable after DELETE");
        assertThat(messages()).anyMatch(message -> message.contains("connection reset"));
    }

    @Test
    void aRateLimitedServerEndsTheRunWithoutFurtherProbes() {
        server.throttleAfterSessions = 3;

        assertThat(audit()).isEmpty();
        assertThat(server.issued).hasSize(3);
        assertThat(server.received).noneMatch(request -> "ping".equals(FakeMcpServer.method(request))
                && !FakeSessionServer.LIVE_SESSION.equals(FakeSessionServer.header(request, "Mcp-Session-Id")));
        assertThat(messages()).anyMatch(message -> message.contains("429"));
        assertThat(server.deleted).containsExactlyInAnyOrderElementsOf(server.issued);
    }

    @Test
    void aServerThatOnlyChecksTheIdFormatIsNotReportedAsUsableAfterDelete() {
        server.acceptsAnySession = true;
        server.malformedIdStatus = 400;

        assertThat(audit()).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("does not enforce"));
    }

    @Test
    void aWellFormedAnyIdThatAuthenticatesDoesNotReachHighThroughAFormatCheck() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.requiresToken = true;
        server.sessionIsCredential = true;
        server.acceptsAnySession = true;
        server.malformedIdStatus = 401;

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
            assertThat(issue.detail()).doesNotContain("checks which ID");
        });
    }

    @Test
    void theNeverIssuedIdControlLooksLikeAnIssuedId() {
        server.deleteIgnored = true;

        audit();

        assertThat(server.received).map(request -> FakeSessionServer.header(request, "Mcp-Session-Id"))
                .filteredOn(server::neverIssued).isNotEmpty()
                .allSatisfy(control -> assertThat(control).hasSameSizeAs(server.issued.get(0))
                        .matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }

    @Test
    void theLiveSessionIdReissuedToProbesIsNamedAndRatedTentative() {
        server.ids = () -> FakeSessionServer.LIVE_SESSION;

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.detail()).contains("own live session ID to new sessions").doesNotContain("bits");
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        });
    }

    @Test
    void aStatelessServerThatChecksAPrefixedFormatIsNotReportedAsUsableAfterDelete() {
        server.ids = () -> "sess_" + UUID.randomUUID().toString().replace("-", "");
        server.statelessFormat = id -> id.matches("sess_[0-9a-f]{32}");

        assertThat(audit()).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("does not enforce"));
    }

    @RepeatedTest(20)
    void aStatelessServerThatChecksVersionFourUuidsIsNeverReportedAsUsableAfterDelete() {
        server.statelessFormat = id -> id.matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");

        assertThat(audit()).isEmpty();
    }

    @Test
    void aPublicServerWhoseSessionlessRequestsGet401StaysLow() {
        auth = new com.mcpscanner.auth.NoAuthStrategy();
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.sessionlessStatus = 401;

        assertThat(audit()).singleElement()
                .satisfies(issue -> assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW));
        assertThat(messages()).anyMatch(message -> message.contains("anonymous initialize opened a session"));
        assertThat(server.deleted).containsExactlyInAnyOrderElementsOf(server.issued);
    }

    @Test
    void anAnonymousProbeIssuedTheLiveIdNeverDeletesTheLiveSession() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> counter.incrementAndGet() <= 8
                ? String.format("session-%06d", counter.get()) : FakeSessionServer.LIVE_SESSION;
        server.sessionlessStatus = 401;

        audit();

        assertThat(messages()).anyMatch(message ->
                message.contains("anonymous initialize opened a session " + FakeSessionServer.LIVE_SESSION));
        assertThat(server.deletesOf(FakeSessionServer.LIVE_SESSION)).isZero();
    }

    @RepeatedTest(20)
    void probeIdsContinuingTheLiveCounterStillReachHigh() {
        AtomicInteger counter = new AtomicInteger(1);
        server.ids = () -> String.format("live-session-%04d", counter.incrementAndGet());
        server.requiresToken = true;
        server.sessionIsCredential = true;

        assertThat(audit()).singleElement()
                .satisfies(issue -> assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH));
    }

    @RepeatedTest(20)
    void probeIdsContinuingTheLiveCounterStillShowReuseAfterDelete() {
        AtomicInteger counter = new AtomicInteger(1);
        server.ids = () -> String.format("live-session-%04d", counter.incrementAndGet());
        server.deleteIgnored = true;

        assertThat(audit()).extracting(AuditIssue::name).contains("MCP session usable after DELETE");
    }

    @Test
    void aPublicServerIgnoringTheConfiguredTokenStaysLow() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.sessionlessStatus = 401;

        assertThat(audit()).singleElement()
                .satisfies(issue -> assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW));
        assertThat(messages()).anyMatch(message -> message.contains("anonymous initialize opened a session"));
    }

    @Test
    void theHighFindingCarriesTheRefusedAnonymousInitialize() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.requiresToken = true;
        server.sessionIsCredential = true;

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.requestResponses()).anySatisfy(exchange -> {
                assertThat(exchange.request().bodyToString()).contains("\"initialize\"");
                assertThat(exchange.request().hasHeader("Authorization")).isFalse();
                assertThat(exchange.response().statusCode()).isEqualTo((short) 401);
            });
        });
    }

    @Test
    void aRateLimitAfterOneSessionIsLoggedAsARateLimit() {
        server.throttleAfterSessions = 1;

        assertThat(audit()).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("429"))
                .noneMatch(message -> message.contains("second session"));
    }

    @Test
    void aDeleteAnsweredWithMethodNotAllowedLogsTheSkippedDeleteTest() {
        server.deleteStatus = 405;

        audit();

        assertThat(messages()).contains(PREFIX + "skipped the DELETE test on " + ENDPOINT
                + " (not applicable: the server answered DELETE with HTTP 405 (clients cannot end sessions))");
    }

    @Test
    void aFreshProbeSessionThatDoesNotAnswerPingLogsAMissingPrerequisite() {
        server.probeOperationsFail = true;
        server.deleteIgnored = true;

        audit();

        assertThat(messages()).contains(PREFIX + "skipped the DELETE test on " + ENDPOINT
                + " (prerequisite missing: a fresh probe session did not answer ping)");
    }

    @Test
    void aServerThatRefusesASecondSessionLogsTheSkippedCheck() {
        server.sessionLimit = 1;

        audit();

        assertThat(messages()).contains(PREFIX + "skipped " + BASE_SUBJECT
                + " (not applicable: the server refused a second session)");
    }

    @Test
    void aServerThatIssuesNoSessionIdLogsTheSkippedCheck() {
        server.ids = () -> null;

        audit();

        assertThat(messages()).contains(PREFIX + "skipped " + BASE_SUBJECT
                + " (not applicable: the server issued no session ID to a new probe session)");
    }

    @Test
    void aLegacySseMessageEndpointLogsTheSkippedCheck() {
        HttpRequestResponse sse = HttpRequestResponse.httpRequestResponse(
                base().request().withPath("/messages/?session_id=live"), base().response());

        check().audit(sse, new ScriptedBurpHttp(server::respond));

        assertThat(messages()).contains(PREFIX + "skipped tools/list at http://target.test/messages/?session_id=live"
                + " (not applicable: probe sessions cannot be opened at a legacy SSE message URL)");
    }

    @Test
    void aRateLimitWhileOpeningProbeSessionsStopsTheCheck() {
        server.throttleAfterSessions = 3;

        audit();

        assertThat(messages()).contains(PREFIX + "stopped " + BASE_SUBJECT
                + " (rate limited: the server answered HTTP 429)");
    }

    @Test
    void aPublicAnonymousSessionLogsTheSkippedBareSessionIdTest() {
        AtomicInteger counter = new AtomicInteger();
        server.ids = () -> String.format("session-%06d", counter.incrementAndGet());
        server.sessionlessStatus = 401;

        audit();

        assertThat(messages()).anyMatch(message -> message.startsWith(PREFIX + "skipped the bare session ID test on "
                + ENDPOINT + " (not applicable: an anonymous initialize opened a session ")
                && message.endsWith(", so sessions are public)"));
    }

    private static SendOnlyBurpHttp droppingDeletes(ScriptedBurpHttp scripted) {
        return new SendOnlyBurpHttp() {
            @Override
            public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions options) {
                HttpRequestResponse exchange = scripted.sendRequest(request, options);
                return request.method().equals("DELETE")
                        ? HttpRequestResponse.httpRequestResponse(request, null) : exchange;
            }
        };
    }

    private List<AuditIssue> audit() {
        return check().audit(base(), new ScriptedBurpHttp(server::respond));
    }

    private HostCheck check() {
        CheckServices services = new CheckServices(log, () -> auth, Optional::empty, Optional::empty,
                PrincipalRoster::empty, AccessLedger.noop(), PrincipalListings.unknown());
        return (HostCheck) new SessionLifecycleCheckFactory().create(services, server::stream);
    }

    private static HttpRequestResponse base() {
        HttpRequest request = HttpRequest.httpRequestFromUrl(ENDPOINT).withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withHeader("MCP-Protocol-Version", FakeMcpServer.LEGACY_VERSION)
                .withHeader("Mcp-Session-Id", FakeSessionServer.LIVE_SESSION)
                .withHeader("Authorization", FakeSessionServer.TOKEN)
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\",\"params\":{}}");
        return HttpRequestResponse.httpRequestResponse(request,
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                        + "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[]}}"));
    }

    private ProtocolHttpRequest lastLiveSessionRequest() {
        return server.received.stream().filter(request ->
                FakeSessionServer.LIVE_SESSION.equals(FakeSessionServer.header(request, "Mcp-Session-Id")))
                .reduce((first, second) -> second).orElseThrow();
    }

    private static List<String> sixtyThreeBitIdsVaryingEveryBitInTheFirstEight() {
        java.security.SecureRandom random = new java.security.SecureRandom();
        while (true) {
            List<Long> values = java.util.stream.Stream.generate(() -> random.nextLong() >>> 1).limit(30).toList();
            long varying = values.stream().limit(8).mapToLong(value -> value ^ values.get(0))
                    .reduce(0, (left, right) -> left | right);
            if (Long.bitCount(varying) == 63) {
                return values.stream().map(value -> String.format("%016x", value)).toList();
            }
        }
    }

    private List<String> messages() {
        return log.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }
}
