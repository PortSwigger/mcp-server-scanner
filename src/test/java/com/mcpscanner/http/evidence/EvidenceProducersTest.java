package com.mcpscanner.http.evidence;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.shared.session.EvidenceProducerFixtures;
import com.mcpscanner.checks.shared.stream.JdkStreamOpener;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.EvidenceTarget;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class EvidenceProducersTest {

    private static final String SENTINEL_PREFIX = "x-mcp-scanner-";

    private EvidenceTarget target;

    @BeforeEach
    void startTarget() throws Exception {
        MontoyaTestFactory.install();
        target = EvidenceTarget.start();
    }

    @AfterEach
    void stopTarget() {
        target.close();
    }

    @FunctionalInterface
    interface Producer {
        List<HttpRequestResponse> evidence(URI endpoint) throws Exception;
    }

    static Stream<Named<Producer>> producers() {
        return Stream.of(
                Named.of("Burp transport", endpoint -> com.mcpscanner.client.EvidenceProducerFixtures
                        .burpTransport(endpoint, EvidenceTarget.credentialed())),
                Named.of("JDK transport recorded by the proxy", endpoint -> com.mcpscanner.proxy
                        .EvidenceProducerFixtures.recordedUpstream(endpoint, EvidenceTarget.credentialed())),
                Named.of("tools/list recorder", endpoint -> com.mcpscanner.client.EvidenceProducerFixtures
                        .toolsListRecorder(endpoint, EvidenceTarget.credentialed())),
                Named.of("legacy SSE POST and stream", endpoint -> com.mcpscanner.client.EvidenceProducerFixtures
                        .legacySse(endpoint, EvidenceTarget.credentialed())),
                Named.of("JDK unstreaming probe", endpoint ->
                        EvidenceProducerFixtures.refusedByBurpAndSentOutside(routedProbe(endpoint))),
                Named.of("raw-socket probe", endpoint -> EvidenceProducerFixtures.refusedByBurpAndSentOutside(
                        routedProbe(endpoint).withUpdatedHeader("Host", "foreign.example"))),
                Named.of("JDK stream opener", endpoint -> List.of(new JdkStreamOpener(McpEventLog.noop())
                        .open(routedProbe(endpoint).withMethod("GET").withBody("")).exchange())),
                Named.of("access backstop", endpoint -> new ReportedEvidence(ScannerSentinels.ALL)
                        .of(issue(routedProbe(endpoint))).requestResponses()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("producers")
    void evidenceShowsTheRequestTheTargetReceivedWithItsCredentialAndNoScannerSentinel(Producer producer)
            throws Exception {
        List<HttpRequestResponse> evidence = producer.evidence(target.endpoint());

        assertThat(evidence).isNotEmpty().allSatisfy(item -> {
            String request = item.request().toByteArray().toString();
            assertThat(request.toLowerCase(java.util.Locale.ROOT)).doesNotContain(SENTINEL_PREFIX);
            assertThat(item.request().headerValue("Authorization")).isEqualTo(EvidenceTarget.CREDENTIAL);
            assertThat(item.response()).isNotNull();
        });
    }

    private static HttpRequest routedProbe(URI endpoint) {
        HttpRequest probe = HttpRequest.httpRequestFromUrl(endpoint.toString()).withMethod("POST")
                .withBody(EvidenceTarget.TOOLS_LIST);
        for (Map.Entry<String, String> header : EvidenceTarget.credentialed().entrySet()) {
            probe = probe.withAddedHeader(header.getKey(), header.getValue());
        }
        return probe.withAddedHeader(ScannerSentinels.IDENTITY_HEADER, "bob")
                .withAddedHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER, ScannerSentinels.SENTINEL_VALUE)
                .withAddedHeader(ScannerSentinels.ROUTED_HEADER, ScannerSentinels.SENTINEL_VALUE);
    }

    private static AuditIssue issue(HttpRequest routed) {
        return AuditIssue.auditIssue("Name", "Detail", "Fix", routed.url(), AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM, "", "", AuditIssueSeverity.HIGH, HttpRequestResponse.httpRequestResponse(
                        routed, burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                                "HTTP/1.1 200 OK\r\n\r\n{}")));
    }
}
