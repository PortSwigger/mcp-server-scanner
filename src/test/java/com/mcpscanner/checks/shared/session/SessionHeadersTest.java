package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SessionHeadersTest {

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private static HttpRequestResponse answeredWith(String headers) {
        return HttpRequestResponse.httpRequestResponse(
                ImmutableHttpRequest.post("http://mcp.example/mcp", Map.of(), "{}"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n" + headers + "\r\n{}"));
    }

    @Test
    void readsTheIssuedSessionIdCaseInsensitively() {
        assertThat(SessionHeaders.issuedBy(answeredWith("mcp-session-id: abc\r\n"))).contains("abc");
    }

    @Test
    void blankMissingOrUnansweredMeansNoSession() {
        assertThat(SessionHeaders.issuedBy(answeredWith("Mcp-Session-Id: \r\n"))).isEmpty();
        assertThat(SessionHeaders.issuedBy(answeredWith(""))).isEmpty();
        assertThat(SessionHeaders.issuedBy(HttpRequestResponse.httpRequestResponse(
                ImmutableHttpRequest.post("http://mcp.example/mcp", Map.of(), "{}"), null))).isEmpty();
        assertThat(SessionHeaders.issuedBy(null)).isEmpty();
    }

    @Test
    void readsTheSessionARequestCarries() {
        assertThat(SessionHeaders.carriedBy(ImmutableHttpRequest.post("http://mcp.example/mcp",
                Map.of("MCP-SESSION-ID", "live"), "{}"))).contains("live");
        assertThat(SessionHeaders.carriedBy(ImmutableHttpRequest.post("http://mcp.example/mcp", Map.of(), "{}")))
                .isEmpty();
    }

    @Test
    void aLegacySseSessionIdComesFromTheQueryOrTheLastPathSegment() {
        assertThat(SessionHeaders.legacySseSessionOf("http://host/messages/?session_id=abc123")).contains("abc123");
        assertThat(SessionHeaders.legacySseSessionOf("http://host/message?sessionId=xyz")).contains("xyz");
        assertThat(SessionHeaders.legacySseSessionOf("http://host/mcp/sessions/281470279102720"))
                .contains("281470279102720");
        assertThat(SessionHeaders.legacySseSessionOf("http://host/")).isEmpty();
    }

    @Test
    void aLegacySseSessionIdIsAlsoReadAsSent() {
        assertThat(SessionHeaders.sentLegacySseSessionOf(ImmutableHttpRequest.post(
                "http://host/messages/?session_id=p%2B1%3D%3D", Map.of(), "{}"))).contains("p%2B1%3D%3D");
        assertThat(SessionHeaders.sentLegacySseSessionOf(ImmutableHttpRequest.post(
                "http://host/mcp/sessions/281470279102720", Map.of(), "{}"))).contains("281470279102720");
    }

    @Test
    void aProbeOnTheLiveSessionsFixedMessageRouteHasNoSessionId() {
        assertThat(SessionHeaders.legacySseSessionOf("http://host/message", "http://host/message")).isEmpty();
        assertThat(SessionHeaders.legacySseSessionOf("http://host/mcp/sessions/2", "http://host/mcp/sessions/1"))
                .contains("2");
        assertThat(SessionHeaders.legacySseSessionOf("http://host/message?sessionId=b", "http://host/message?sessionId=a"))
                .contains("b");
    }
}
