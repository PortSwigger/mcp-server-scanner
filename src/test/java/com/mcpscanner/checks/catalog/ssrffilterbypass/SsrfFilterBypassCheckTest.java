package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.SettlingLateIssues;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.checks.shared.collaborator.FakeCollaborator;
import com.mcpscanner.checks.shared.collaborator.TestWatches;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.scan.field.McpFieldGenerator;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SsrfFilterBypassCheckTest {

    private static final String ENDPOINT = "http://mcp.example.test:8191/mcp";
    private static final String URL_FIELD = "MCP field: params.arguments.url";
    private static final String FETCH_CALL = "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{"
            + "\"name\":\"fetch\",\"arguments\":{\"url\":\"https://docs.example.test/a\",\"max_length\":5000}}}";
    private static final String OTHER_CALL = "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{"
            + "\"name\":\"archive_page\",\"arguments\":{\"url\":\"https://docs.example.test/a\"}}}";
    private static final int REFUSAL_PROBES = 2;
    private static final int SPELLINGS = AddressSpelling.values().length;
    private static final int HIT_REPLY = REFUSAL_PROBES + 1;
    private static final int CONFIRMATIONS = 3;

    private final FilteringFetchTool tool = new FilteringFetchTool();
    private final McpEventLog eventLog = new McpEventLog(null);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsASpellingTheFilterMissesWhenTheSameSpellingOfTheCollaboratorAddressIsFetched() {
        tool.refusing(FilteringFetchTool.DOTTED_ONLY_FILTER::contains);

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP server SSRF address filter bypass");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("tools/call fetch").contains("http://[::ffff:7f00:1]:8191/")
                    .contains("http://[::ffff:c633:6407]/").contains("IPv4-mapped IPv6 address in hexadecimal")
                    .doesNotContain("dotted form");
            assertThat(issue.requestResponses()).extracting(SsrfFilterBypassCheckTest::urlArgument).containsExactly(
                    "http://127.0.0.1:8191/", "http://[::ffff:7f00:1]:8191/", "http://[::ffff:c633:6407]/");
            assertThat(issue.detail()).doesNotContain("[::1]").doesNotContain("0.0.0.0");
        });
        assertThat(tool.fetchedUrls()).contains("http://[::ffff:7f00:1]:8191/");
    }

    @Test
    void isFirmWhenTheLoopbackReplyHoldsTheTargetsOwnPage() {
        tool.refusing(FilteringFetchTool.DOTTED_ONLY_FILTER::contains).servingTheHomePageOnLoopback();

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("own page");
        });
    }

    @Test
    void attachesOnlyTheFirstProvenSpellingWithItsControlAndListsTheOthers() {
        tool.refusing("127.0.0.1"::equals);

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("in hexadecimal", "in dotted form", "as one decimal number",
                            "in octal", "shortened")
                    .contains("The refusal, the IPv4-mapped IPv6 address in hexadecimal loopback probe and its "
                            + "Collaborator control are attached.");
            assertThat(issue.requestResponses()).extracting(SsrfFilterBypassCheckTest::urlArgument).containsExactly(
                    "http://127.0.0.1:8191/", "http://[::ffff:7f00:1]:8191/", "http://[::ffff:c633:6407]/");
        });
    }

    @Test
    void attachesTheProvenSpellingWhoseReplyShowsTheTargetPageWhenFirm() {
        tool.refusing("127.0.0.1"::equals).servingTheHomePageOnLoopbackTo("0x7f000001"::equals);

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("in dotted form").contains("The refusal, the IPv4 address as one "
                    + "hexadecimal number loopback probe and its Collaborator control are attached.");
            assertThat(issue.requestResponses()).hasSize(3);
            assertThat(urlArgument(issue.requestResponses().get(1))).isEqualTo("http://0x7f000001:8191/");
            assertThat(urlArgument(issue.requestResponses().get(2))).startsWith("http://0xc6336407/");
        });
    }

    @Test
    void staysSilentWhenTheFilterRefusesEverySpelling() {
        tool.refusing(host -> !host.contains("c633") && !host.contains("198.51") && !host.contains("3325256711"));

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).isEmpty();
        assertThat(tool.received()).hasSize(REFUSAL_PROBES + SPELLINGS);
    }

    @Test
    void staysSilentWhenTheRefusalItselfChangesWhileTheSpellingsAreSent() {
        tool.refusing(FilteringFetchTool.DOTTED_ONLY_FILTER::contains)
                .refusingWith(received -> "blocked at 10:00:0" + (received <= REFUSAL_PROBES ? 1 : 2));

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).isEmpty();
        assertThat(tool.fetchedUrls()).doesNotContain("http://[::ffff:c633:6407]/");
        assertThat(infoLines()).anyMatch(line -> line.contains("refusal changed"));
    }

    @Test
    void comparesARefusalThatEchoesTheUrlOnTheDefaultHttpPort() {
        tool.refusing(FilteringFetchTool.DOTTED_ONLY_FILTER::contains).refusingWith(received -> "blocked");
        CheckUnderTest check = new CheckUnderTest(Optional.of(tool.collaborator()));

        List<AuditIssue> issues = check.audit(FETCH_CALL, URL_FIELD, "http://mcp.example.test/mcp");

        assertThat(issues).hasSize(1);
        assertThat(tool.received().get(0).bodyToString()).contains("http://127.0.0.1:80/");
    }

    @Test
    void stopsAfterTheRefusalProbesWhenLoopbackIsNotRefusedAlike() {
        tool.refusing(host -> false).failingToConnectWith(url -> url.endsWith(":8191/")
                ? "<html>the target answering on its own port</html>" : "connect ECONNREFUSED " + url);

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).isEmpty();
        assertThat(tool.received()).hasSize(REFUSAL_PROBES);
        assertThat(infoLines()).anyMatch(line -> line.contains("no address filter was shown"));
    }

    @Test
    void staysSilentOnAnUnfilteredFetcherThatEchoesTheCanonicalLoopbackUrl() {
        tool.refusing(host -> false).failingToConnectWith(url -> "Failed to fetch http://127.0.0.1:"
                + url.replaceAll(".*:(\\d+)/$", "$1") + "/robots.txt due to a connection issue");

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).isEmpty();
        assertThat(tool.received()).hasSize(REFUSAL_PROBES + SPELLINGS);
    }

    @Test
    void staysSilentWhenTheChangedReplyComesFromAParserThatRejectsTheSpelling() {
        tool.refusing(FilteringFetchTool.DOTTED_ONLY_FILTER::contains).parsingOnly(host -> !host.startsWith("[::ffff:")
                || host.contains("."));

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).isEmpty();
        assertThat(tool.fetchedUrls()).isEmpty();
    }

    @Test
    void probesOnlyTheUrlArgumentOfAFetchOperation() {
        List<AuditIssue> other = audit(OTHER_CALL, URL_FIELD, Optional.of(tool.collaborator()));
        List<AuditIssue> limit = audit(FETCH_CALL, "MCP field: params.arguments.max_length",
                Optional.of(tool.collaborator()));

        assertThat(other).isEmpty();
        assertThat(limit).isEmpty();
        assertThat(tool.received()).isEmpty();
        assertThat(infoLines()).anyMatch(line -> line.contains("not the URL argument of a fetch"));
    }

    @Test
    void sendsNothingWithoutCollaborator() {
        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.empty());

        assertThat(issues).isEmpty();
        assertThat(tool.received()).isEmpty();
        assertThat(infoLines()).anyMatch(line -> line.contains("Burp Collaborator is unavailable"));
    }

    @Test
    void sendsNothingWhenTheCollaboratorServerHasNoAddress() {
        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(new FakeCollaborator()));

        assertThat(issues).isEmpty();
        assertThat(tool.received()).isEmpty();
        assertThat(infoLines()).anyMatch(line -> line.contains("no IPv4 address"));
    }

    @Test
    void stopsProbingAFieldOnceItsBypassIsReported() {
        tool.refusing(FilteringFetchTool.DOTTED_ONLY_FILTER::contains);
        CheckUnderTest check = new CheckUnderTest(Optional.of(tool.collaborator()));
        check.audit(FETCH_CALL, URL_FIELD);
        int afterFirst = tool.received().size();

        List<AuditIssue> second = check.audit(FETCH_CALL, URL_FIELD);

        assertThat(second).isEmpty();
        assertThat(tool.received()).hasSize(afterFirst);
    }

    @Test
    void stopsAtTheFirstRateLimitedReply() {
        tool.refusing(FilteringFetchTool.DOTTED_ONLY_FILTER::contains).rateLimitingAfter(1);

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).isEmpty();
        assertThat(tool.received()).hasSize(2);
        assertThat(infoLines()).anyMatch(line -> line.contains("rate"));
    }

    @Test
    void confirmsAndReportsAHitWhoseReplySaysTheRateLimitQuotaIsSpent() {
        tool.refusing(FilteringFetchTool.DOTTED_ONLY_FILTER::contains).servingTheHomePageOnLoopback()
                .spendingQuotaFrom(HIT_REPLY);

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.requestResponses()).extracting(SsrfFilterBypassCheckTest::urlArgument).containsExactly(
                    "http://127.0.0.1:8191/", "http://[::ffff:7f00:1]:8191/", "http://[::ffff:c633:6407]/");
        });
        assertThat(tool.received()).hasSize(HIT_REPLY + CONFIRMATIONS);
    }

    @Test
    void stopsProbingOnceAReplyWithoutAHitSaysTheRateLimitQuotaIsSpent() {
        tool.refusing(FilteringFetchTool.DOTTED_ONLY_FILTER::contains).spendingQuotaFrom(1);

        List<AuditIssue> issues = audit(FETCH_CALL, URL_FIELD, Optional.of(tool.collaborator()));

        assertThat(issues).isEmpty();
        assertThat(tool.received()).hasSize(1);
        assertThat(infoLines()).anyMatch(line -> line.contains("rate limit"));
    }

    private List<AuditIssue> audit(String body, String fieldName, Optional<CollaboratorClient> client) {
        return new CheckUnderTest(client).audit(body, fieldName);
    }

    private List<String> infoLines() {
        return eventLog.snapshot().stream().filter(entry -> entry.level() == McpEventLog.Level.INFO)
                .map(McpEventLog.LogEntry::message).toList();
    }

    private final class CheckUnderTest {

        private final SsrfFilterBypassCheck check;
        private final SettlingLateIssues late;

        CheckUnderTest(Optional<CollaboratorClient> client) {
            CollaboratorWatch watch = TestWatches.immediate(() -> client);
            this.late = new SettlingLateIssues(watch);
            this.check = new SsrfFilterBypassCheck(eventLog, watch, late, BurpNativeJsonRpcFields.ABSENT);
        }

        List<AuditIssue> audit(String body, String fieldName) {
            return audit(body, fieldName, ENDPOINT);
        }

        List<AuditIssue> audit(String body, String fieldName, String endpoint) {
            HttpRequest request = mcpRequest(endpoint, body);
            HttpRequestResponse base = HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{}}"));
            List<AuditIssue> issues = new ArrayList<>(check.audit(base, field(request, fieldName), tool.http()));
            assertThat(issues).as("the audit returns before any Collaborator interaction is read").isEmpty();
            issues.addAll(late.settle(check));
            return issues;
        }
    }

    private static String urlArgument(HttpRequestResponse exchange) {
        String body = exchange.request().bodyToString();
        int start = body.indexOf("\"url\":\"") + "\"url\":\"".length();
        String url = body.substring(start, body.indexOf('"', start));
        return url.replaceAll("/[a-z0-9]+\\." + FakeCollaborator.DOMAIN.replace(".", "\\.") + ".*", "/");
    }

    private static HttpRequest mcpRequest(String endpoint, String body) {
        return HttpRequest.httpRequestFromUrl(endpoint).withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withHeader("Accept", "application/json, text/event-stream")
                .withBody(body);
    }

    private static AuditInsertionPoint field(HttpRequest request, String name) {
        return new McpFieldGenerator(() -> true).fieldsOf(request).stream()
                .filter(point -> point.name().equals(name)).findFirst().orElseThrow();
    }
}
