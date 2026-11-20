package com.mcpscanner.cvetargets.burp;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.cvetargets.run.IssueSummary;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LegacySseEvidenceShapeTest {

    private static final String POST_ACCEPTED = "POST /messages?session_id=1 HTTP/1.1 => HTTP/1.1 202 Accepted";
    private static final String STREAM_EVENT = "GET /sse HTTP/1.1 => HTTP/1.1 200 OK | text/event-stream";
    private static final String COMPOSITE = "POST /messages?session_id=1 HTTP/1.1 => HTTP/1.1 200 OK | text/event-stream";
    private static final String UNANSWERED = "POST /messages?session_id=1 HTTP/1.1 => (no response)";

    @Test
    void acceptsEachPostFollowedByItsStreamEvent() {
        assertThatCode(() -> requireOnSse(POST_ACCEPTED, STREAM_EVENT, POST_ACCEPTED, STREAM_EVENT))
                .doesNotThrowAnyException();
    }

    @Test
    void refusesAPostAnsweredByTheStream() {
        assertThatThrownBy(() -> requireOnSse(COMPOSITE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Command injection")
                .hasMessageContaining(COMPOSITE);
    }

    @Test
    void refusesAStreamEventWithoutThePostBeforeIt() {
        assertThatThrownBy(() -> requireOnSse(STREAM_EVENT, POST_ACCEPTED))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Command injection")
                .hasMessageContaining(STREAM_EVENT);
    }

    @Test
    void refusesAStreamEventFollowingAnotherStreamEvent() {
        assertThatThrownBy(() -> requireOnSse(POST_ACCEPTED, STREAM_EVENT, STREAM_EVENT))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(STREAM_EVENT);
    }

    @Test
    void toleratesItemsWithNoResponse() {
        assertThatCode(() -> requireOnSse(UNANSWERED, POST_ACCEPTED, STREAM_EVENT, UNANSWERED))
                .doesNotThrowAnyException();
    }

    @Test
    void doesNotCheckAStreamableHttpArm() {
        assertThatCode(() -> LegacySseEvidenceShape.require(TransportType.STREAMABLE_HTTP,
                List.of(issue(COMPOSITE, STREAM_EVENT)))).doesNotThrowAnyException();
    }

    private static void requireOnSse(String... evidence) {
        LegacySseEvidenceShape.require(TransportType.SSE, List.of(issue(evidence)));
    }

    private static IssueSummary issue(String... evidence) {
        return new IssueSummary("Command injection", AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
                "http://127.0.0.1:41000", "detail", List.of(evidence));
    }
}
