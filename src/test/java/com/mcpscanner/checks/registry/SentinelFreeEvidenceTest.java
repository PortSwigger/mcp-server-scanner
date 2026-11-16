package com.mcpscanner.checks.registry;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

class SentinelFreeEvidenceTest {

    private static final String URL = "https://mcp.example.test/mcp";

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void removesEverySentinelHeaderFromTheRequestAndResponseOfEveryEvidenceItemWhateverTheCase() {
        AuditIssue issue = issue(exchangeWithAllSentinels(String::toString),
                exchangeWithAllSentinels(name -> name.toLowerCase(Locale.ROOT)),
                exchangeWithAllSentinels(name -> name.toUpperCase(Locale.ROOT)));

        List<HttpRequestResponse> evidence = SentinelFreeEvidence.of(issue).requestResponses();

        assertThat(evidence).hasSize(3).allSatisfy(item -> {
            assertThat(item.request().headers()).noneMatch(header -> ScannerSentinels.ALL.contains(header.name()));
            assertThat(item.response().headers()).noneMatch(header -> ScannerSentinels.ALL.contains(header.name()));
            assertThat(item.request().hasHeader("Content-Type")).isTrue();
            assertThat(item.response().hasHeader("Content-Type")).isTrue();
        });
    }

    @Test
    void keepsTheIssueTextAndRatings() {
        AuditIssue cleaned = SentinelFreeEvidence.of(issue(exchangeWithAllSentinels(String::toString)));

        assertThat(cleaned.name()).isEqualTo("Name");
        assertThat(cleaned.detail()).isEqualTo("Detail");
        assertThat(cleaned.baseUrl()).isEqualTo(URL);
        assertThat(cleaned.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(cleaned.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
    }

    @Test
    void returnsTheSameIssueWhenNoEvidenceCarriesASentinel() {
        AuditIssue clean = issue(HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl(URL), HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\nok")));

        assertThat(SentinelFreeEvidence.of(clean)).isSameAs(clean);
    }

    @Test
    void cleansEveryIssueInAList() {
        List<AuditIssue> cleaned = SentinelFreeEvidence.of(List.of(
                issue(exchangeWithAllSentinels(String::toString)), issue(exchangeWithAllSentinels(String::toString))));

        assertThat(cleaned).allSatisfy(issue -> assertThat(issue.requestResponses().get(0).request().headers())
                .noneMatch(header -> ScannerSentinels.ALL.contains(header.name())));
    }

    @Test
    void removesAResponseSentinelThatTheHeaderViewDoesNotListButTheWireBytesCarry() {
        HttpResponse real = HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + ScannerSentinels.EXCHANGE_HEADER + ": 0123456789abcdef0123456789abcdef\r\n\r\n{\"ok\":true}");
        HttpResponse unlisted = org.mockito.Mockito.mock(HttpResponse.class);
        org.mockito.Mockito.lenient().when(unlisted.headers()).thenReturn(List.of());
        burp.api.montoya.core.ByteArray wire = real.toByteArray();
        org.mockito.Mockito.lenient().when(unlisted.toByteArray()).thenReturn(wire);
        AuditIssue issue = issue(HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl(URL), unlisted));

        HttpResponse cleaned = SentinelFreeEvidence.of(issue).requestResponses().get(0).response();

        assertThat(cleaned.toByteArray().toString().toLowerCase(Locale.ROOT)).doesNotContain("x-mcp-scanner-");
        assertThat(cleaned.toByteArray().toString()).contains("Content-Type: application/json").contains("{\"ok\":true}");
    }

    private static HttpRequestResponse exchangeWithAllSentinels(java.util.function.UnaryOperator<String> casing) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(URL).withMethod("POST")
                .withHeader("Content-Type", "application/json").withBody("{}");
        StringBuilder response = new StringBuilder("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n");
        for (String name : ScannerSentinels.ALL) {
            request = request.withHeader(casing.apply(name), "value");
            response.append(casing.apply(name)).append(": value\r\n");
        }
        return HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse(response + "\r\n{}"));
    }

    private static AuditIssue issue(HttpRequestResponse... evidence) {
        return AuditIssue.auditIssue("Name", "Detail", "Remediation", URL, AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM, "Background", "Remediation background", AuditIssueSeverity.MEDIUM, evidence);
    }
}
