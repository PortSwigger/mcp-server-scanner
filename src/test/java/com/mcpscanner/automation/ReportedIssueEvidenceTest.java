package com.mcpscanner.automation;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RawHttpRequestStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ReportedIssueEvidenceTest {

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void summarisesEachEvidenceExchangeByItsRequestLineStatusLineAndContentType() {
        HttpRequestResponse streamed = HttpRequestResponse.httpRequestResponse(
                RawHttpRequestStub.fromRaw("POST /messages?session_id=1 HTTP/1.1\r\nHost: t\r\n\r\n{}"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n"
                        + "event: message\r\ndata: {}\r\n\r\n"));
        HttpRequestResponse unanswered = HttpRequestResponse.httpRequestResponse(
                RawHttpRequestStub.fromRaw("POST /messages HTTP/1.1\r\nHost: t\r\n\r\n{}"), null);

        ReportedIssue reported = ReportedIssue.filedByTheExtension(issue(streamed, unanswered));

        assertThat(reported.evidence()).containsExactly(
                "POST /messages?session_id=1 HTTP/1.1 => HTTP/1.1 200 OK | text/event-stream",
                "POST /messages HTTP/1.1 => (no response)");
    }

    private static AuditIssue issue(HttpRequestResponse... evidence) {
        return AuditIssue.auditIssue("Name", "Detail", "", "http://t/messages", AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM, "", "", AuditIssueSeverity.HIGH, List.of(evidence));
    }
}
