package com.mcpscanner.automation;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.scan.request.ClientRegistrationMessage;
import com.mcpscanner.scan.request.McpMessage;
import com.mcpscanner.scan.request.ScanMessageRenderer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BaseRequestLedgerTest {

    private final BaseRequestLedger ledger = new BaseRequestLedger();
    private final ScanMessageRenderer delegate = mock(ScanMessageRenderer.class);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void remembersEveryRequestTheLaunchRendersByMethodPathAndBody() {
        HttpRequest toolCall = request("POST", "/mcp", "{\"method\":\"tools/call\"}");
        HttpRequest registration = request("POST", "/register", "{\"client_name\":\"x\"}");
        when(delegate.renderJsonRpc(any(), any(), any())).thenReturn(toolCall);
        when(delegate.renderClientRegistration(any())).thenReturn(registration);
        ScanMessageRenderer recording = ledger.recording(delegate);

        assertThat(recording.renderJsonRpc("http://t/mcp", mock(McpMessage.class), Map.of())).isSameAs(toolCall);
        assertThat(recording.renderClientRegistration(mock(ClientRegistrationMessage.class))).isSameAs(registration);

        assertThat(ledger.contains(request("POST", "/mcp", "{\"method\":\"tools/call\"}"))).isTrue();
        assertThat(ledger.contains(request("POST", "/register", "{\"client_name\":\"x\"}"))).isTrue();
        assertThat(ledger.contains(request("POST", "/mcp", "{\"method\":\"tools/call'\"}"))).isFalse();
        assertThat(ledger.contains(request("GET", "/mcp", "{\"method\":\"tools/call\"}"))).isFalse();
    }

    @Test
    void tellsAHeaderVariantFromTheLaunchedRequestButIgnoresHeadersBurpOrTheSendPathManage() {
        HttpRequest launched = request("POST", "/mcp", "{}", List.of(
                header("Host", "127.0.0.1:1"), header("Accept", "application/json"),
                header("X-Mcp-Scanner-Audit-Capability", "capability")));
        when(delegate.renderJsonRpc(any(), any(), any())).thenReturn(launched);
        ledger.recording(delegate).renderJsonRpc("http://t/mcp", mock(McpMessage.class), Map.of());

        assertThat(ledger.contains(request("POST", "/mcp", "{}", List.of(
                header("accept", "application/json"), header("Content-Length", "2"),
                header("Host", "127.0.0.1:2"), header("X-Mcp-Scanner-Audit-Capability", "capability"),
                header("X-Mcp-Scanner-Routed", "routing-key"))))).isTrue();
        assertThat(ledger.contains(request("POST", "/mcp", "{}", List.of(
                header("Accept", "application/json'"), header("X-Mcp-Scanner-Audit-Capability", "capability"))))).isFalse();
        assertThat(ledger.contains(request("POST", "/mcp", "{}", List.of(
                header("Accept", "application/json"), header("X-Mcp-Scanner-Audit-Capability", "capability"),
                header("X-Forwarded-Host", "evil.test"))))).isFalse();
    }

    @Test
    void tellsAFuzzedScannerSentinelFromTheLaunchedRequest() {
        HttpRequest launched = request("POST", "/mcp", "{}", List.of(
                header("X-Mcp-Scanner-Audit-Capability", "capability"),
                header("X-Mcp-Scanner-Framed-Operation", "framed")));
        when(delegate.renderJsonRpc(any(), any(), any())).thenReturn(launched);
        ledger.recording(delegate).renderJsonRpc("http://t/mcp", mock(McpMessage.class), Map.of());

        assertThat(ledger.contains(request("POST", "/mcp", "{}", List.of(
                header("X-Mcp-Scanner-Audit-Capability", "capability\"|ping -n 21 127.0.0.1 ||"),
                header("X-Mcp-Scanner-Framed-Operation", "framed"))))).isFalse();
        assertThat(ledger.contains(request("POST", "/mcp", "{}", List.of(
                header("X-Mcp-Scanner-Audit-Capability", "capability"),
                header("X-Mcp-Scanner-Framed-Operation", "framed''"))))).isFalse();
    }

    @Test
    void matchesALaunchedRegistrationAfterTheCleanupHandlerRemovesItsSentinel() {
        HttpRequest registration = request("POST", "/register", "{\"client_name\":\"x\"}", List.of(
                header("Content-Type", "application/json"), header("X-Mcp-Scanner-Registration", "1")));
        when(delegate.renderClientRegistration(any())).thenReturn(registration);
        ledger.recording(delegate).renderClientRegistration(mock(ClientRegistrationMessage.class));

        assertThat(ledger.contains(request("POST", "/register", "{\"client_name\":\"x\"}", List.of(
                header("Content-Type", "application/json"))))).isTrue();
    }

    @Test
    void forgetsEverythingWhenCleared() {
        HttpRequest toolCall = request("POST", "/mcp", "{}");
        when(delegate.renderJsonRpc(any(), any(), any())).thenReturn(toolCall);
        ledger.recording(delegate).renderJsonRpc("http://t/mcp", mock(McpMessage.class), Map.of());

        ledger.clear();

        assertThat(ledger.contains(toolCall)).isFalse();
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        when(header.name()).thenReturn(name);
        when(header.value()).thenReturn(value);
        return header;
    }

    static HttpRequest request(String method, String path, String body) {
        return request(method, path, body, List.of());
    }

    static HttpRequest request(String method, String path, String body, List<HttpHeader> headers) {
        HttpRequest request = mock(HttpRequest.class);
        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(method);
        when(request.path()).thenReturn(path);
        when(request.bodyToString()).thenReturn(body);
        return request;
    }
}
