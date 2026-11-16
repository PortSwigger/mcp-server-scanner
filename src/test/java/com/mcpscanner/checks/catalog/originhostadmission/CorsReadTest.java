package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.checks.shared.session.ProbeSessions;
import com.mcpscanner.checks.shared.stream.ScriptedEventStreams;
import com.mcpscanner.checks.shared.stream.StreamOpener;
import com.mcpscanner.checks.shared.stream.StreamOpening;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.SseProbeStreams;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;

import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.LOOPBACK_URL;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.TOOLS_RESULT;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.captured;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.toolsList;
import static org.assertj.core.api.Assertions.assertThat;

class CorsReadTest {

    private static final String WILDCARD = "Access-Control-Allow-Origin: *";
    private static final String ALL_HEADERS = "Access-Control-Allow-Headers: *";
    private static final String REFLECTED = "Access-Control-Allow-Origin: " + CorsProbe.FOREIGN_ORIGIN;
    private static final String CREDENTIALS = "Access-Control-Allow-Credentials: true";
    private static final String SSE_MESSAGE_URL = "http://127.0.0.1:8765/message?sessionId=abc";
    private static final String SSE_STREAM_URL = "http://127.0.0.1:8765/sse";

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void aWildcardCorsServerWithoutAuthIsAHighCrossOriginRead() {
        AdmissionServers.Server server = new AdmissionServers.Server(cors(204, List.of(WILDCARD, ALL_HEADERS),
                List.of(WILDCARD)));

        AuditIssue issue = corsIssue(check(NoAuthStrategy::new).audit(captured(toolsList(LOOPBACK_URL)), server.http));

        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.requestResponses()).hasSize(4);
        assertThat(issue.requestResponses().get(0).request().method()).isEqualTo("OPTIONS");
        assertThat(issue.detail()).contains("Access-Control-Allow-Origin: *");
    }

    @Test
    void aBearerOnlyServerIsLow() {
        AdmissionServers.Server server = new AdmissionServers.Server(cors(204,
                List.of(WILDCARD, "Access-Control-Allow-Headers: authorization, content-type"), List.of(WILDCARD)));

        AuditIssue issue = corsIssue(check(() -> new BearerTokenAuthStrategy("live"))
                .audit(captured(toolsList(LOOPBACK_URL)), server.http));

        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
    }

    @Test
    void aCookieServerReflectingTheOriginWithCredentialsIsHigh() {
        AdmissionServers.Server server = new AdmissionServers.Server(cors(204,
                List.of(REFLECTED, CREDENTIALS, "Access-Control-Allow-Headers: content-type"),
                List.of(REFLECTED, CREDENTIALS)));
        HttpRequest seed = toolsList(LOOPBACK_URL).withHeader("Cookie", "session=1");

        AuditIssue issue = corsIssue(check(NoAuthStrategy::new).audit(captured(seed), server.http));

        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void aRefusedPreflightStopsAfterOneRequest() {
        AdmissionServers.Server server = new AdmissionServers.Server(cors(405, List.of(), List.of(WILDCARD)));

        List<AuditIssue> issues = check(NoAuthStrategy::new).audit(captured(toolsList(LOOPBACK_URL)), server.http);

        assertThat(issues).extracting(AuditIssue::name).doesNotContain(CorsIssues.ISSUE_NAME);
        assertThat(server.received).filteredOn(request -> request.method().equals("OPTIONS")).hasSize(1);
        assertThat(server.received).hasSize(8);
    }

    @Test
    void anApprovedPreflightWithAnUnreadableReplyIsSilent() {
        AdmissionServers.Server server = new AdmissionServers.Server(cors(204, List.of(WILDCARD, ALL_HEADERS),
                List.of()));

        List<AuditIssue> issues = check(NoAuthStrategy::new).audit(captured(toolsList(LOOPBACK_URL)), server.http);

        assertThat(issues).extracting(AuditIssue::name).doesNotContain(CorsIssues.ISSUE_NAME);
    }

    @Test
    void aServerRefusingTheForeignOriginIsSilentDespiteWildcardCors() {
        AdmissionServers.Server server = new AdmissionServers.Server(request -> request.method().equals("OPTIONS")
                ? response(204, List.of(WILDCARD, ALL_HEADERS), "")
                : request.hasHeader("Origin") ? AdmissionServers.status(403, "{}")
                : response(200, List.of(WILDCARD), TOOLS_RESULT));

        assertThat(check(NoAuthStrategy::new).audit(captured(toolsList(LOOPBACK_URL)), server.http))
                .extracting(AuditIssue::name).doesNotContain(CorsIssues.ISSUE_NAME);
    }

    @Test
    void aLegacySseStreamReadableCrossOriginWithoutCredentialsIsHigh() {
        List<HttpRequest> opened = new ArrayList<>();
        StreamOpener opener = request -> {
            opened.add(request);
            return new StreamOpening(HttpRequestResponse.httpRequestResponse(request,
                    HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" + WILDCARD
                            + "\r\n\r\nevent: endpoint\n")), true);
        };

        AuditIssue issue = corsIssue(sseCheck(opener).audit(captured(toolsList(SSE_MESSAGE_URL)), sseServer().http));

        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(opened).singleElement().satisfies(request -> {
            assertThat(request.url()).isEqualTo(SSE_STREAM_URL);
            assertThat(request.headerValue("Origin")).isEqualTo(CorsProbe.FOREIGN_ORIGIN);
            assertThat(request.hasHeader("Authorization")).isFalse();
        });
    }

    @Test
    void aLegacySseStreamRefusingAnonymousClientsIsSilent() {
        StreamOpener opener = request -> new StreamOpening(HttpRequestResponse.httpRequestResponse(request,
                response(401, List.of(), "Unauthorized")), false);

        List<AuditIssue> issues = sseCheck(opener).audit(captured(toolsList(SSE_MESSAGE_URL)), sseServer().http);

        assertThat(issues).extracting(AuditIssue::name).doesNotContain(CorsIssues.ISSUE_NAME);
    }

    private static AdmissionServers.Server sseServer() {
        return new AdmissionServers.Server(request -> AdmissionServers.status(403, "{}"));
    }

    private static Function<HttpRequest, HttpResponse> cors(int preflightStatus, List<String> preflightHeaders,
                                                            List<String> replyHeaders) {
        return request -> request.method().equals("OPTIONS")
                ? response(preflightStatus, preflightHeaders, "")
                : response(200, replyHeaders, TOOLS_RESULT);
    }

    private static HttpResponse response(int status, List<String> headers, String body) {
        StringBuilder head = new StringBuilder("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\n");
        headers.forEach(header -> head.append(header).append("\r\n"));
        return HttpResponse.httpResponse(head + "\r\n" + body);
    }

    private static AuditIssue corsIssue(List<AuditIssue> issues) {
        return issues.stream().filter(issue -> issue.name().equals(CorsIssues.ISSUE_NAME)).findFirst().orElseThrow();
    }

    private static OriginHostAdmissionCheck check(Supplier<AuthStrategy> strategy) {
        return new OriginHostAdmissionCheck(McpEventLog.noop(), new CredentialHeaders(strategy), Optional::empty,
                ScriptedEventStreams.none(), new ProbeSessions(strategy));
    }

    private static OriginHostAdmissionCheck sseCheck(StreamOpener opener) {
        return new OriginHostAdmissionCheck(McpEventLog.noop(),
                new CredentialHeaders(() -> new BearerTokenAuthStrategy("live")),
                () -> Optional.of(HttpService.httpService("127.0.0.1", 40000, false)), ScriptedEventStreams.none(),
                new ProbeSessions(NoAuthStrategy::new),
                () -> Optional.of(SseProbeStreams.at(SSE_STREAM_URL, headers -> {
                    throw new UnsupportedOperationException();
                })), opener);
    }
}
