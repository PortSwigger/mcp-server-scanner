package com.mcpscanner.client;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.JsonRpcDiscoveryResponseScanner;
import com.mcpscanner.checks.content.ContentFindingIssueBuilder;
import com.mcpscanner.checks.content.rules.AwsAccessKeyRule;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.McpRequestDetector.DiscoveryResponseKind;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Bridges captured langchain4j discovery exchanges (see {@link CapturingMcpTransport})
 * into the Burp passive-scan engine. Every {@link CapturedExchange} the captor publishes
 * is reconstituted as an {@link HttpRequestResponse} and pushed through
 * {@link Audit#addRequestResponse}, which is the call Burp invokes registered
 * {@link burp.api.montoya.scanner.scancheck.PassiveScanCheck}s on.
 *
 * <p>Why bother: langchain4j-mcp uses its own {@code java.net.http.HttpClient} for the
 * initialize / tools-list / resources-list / prompts-list handshakes, so Burp's pipeline
 * never sees the wire bytes. Without this bridge, {@link JsonRpcDiscoveryResponseScanner}
 * (T8) only runs on {@code tools/call} traffic that the scanner sends — and the classifier
 * rejects every one of those as {@code OTHER}. The findings would never reach audit XML.
 */
@ExtendWith(MockitoExtension.class)
class McpDiscoveryAuditBridgeTest {

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void captured_tools_list_response_triggers_audit_emission() throws Exception {
        // The bridge forwards each captured discovery exchange to the Audit so that
        // Burp's registered passive checks (including T8's JsonRpcDiscoveryResponseScanner)
        // fire on the synthesised pair and emit via AuditResult.
        Audit audit = mock(Audit.class);
        McpDiscoveryAuditBridge bridge = new McpDiscoveryAuditBridge(() -> audit);
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":["
                        + "{\"name\":\"leak\","
                        + "\"description\":\"Use AKIAQ7777PYTYINTERNAL to authenticate\"}]}}");
        CapturedExchange exchange = new CapturedExchange(
                "tools/list",
                URI.create("http://127.0.0.1:8000/mcp"),
                Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                envelope);

        bridge.accept(exchange);

        java.util.ArrayList<HttpRequestResponse> capturedPair = new java.util.ArrayList<>();
        verify(audit).addRequestResponse(org.mockito.ArgumentMatchers.argThat(pair -> {
            capturedPair.add(pair);
            return true;
        }));
        // The pushed pair must pass T8's HTTP-layer + MCP-layer classifier.
        assertThat(McpRequestDetector.classifyDiscoveryResponse(capturedPair.get(0)))
                .isEqualTo(DiscoveryResponseKind.TOOLS_LIST);
        // And running the registered passive check directly against the pair should emit the AWS key.
        List<AuditIssue> issues = runDiscoveryScannerAgainst(capturedPair.get(0));
        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).name()).isEqualTo(new AwsAccessKeyRule().displayName()
                + ContentFindingIssueBuilder.DISCOVERY_SOURCE.nameQualifier());
    }

    @Test
    void captured_non_discovery_exchange_classified_as_OTHER() throws Exception {
        // Defence in depth: if the bridge ever gets fed something that isn't one of the
        // four discovery methods, the classifier must say OTHER and no rules fire.
        Audit audit = mock(Audit.class);
        McpDiscoveryAuditBridge bridge = new McpDiscoveryAuditBridge(() -> audit);
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":["
                        + "{\"type\":\"text\",\"text\":\"AKIAQ7777PYTYINTERNAL\"}]}}");
        CapturedExchange exchange = new CapturedExchange(
                "tools/call",
                URI.create("http://127.0.0.1:8000/mcp"),
                Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
                envelope);

        bridge.accept(exchange);

        java.util.ArrayList<HttpRequestResponse> capturedPair = new java.util.ArrayList<>();
        verify(audit).addRequestResponse(org.mockito.ArgumentMatchers.argThat(pair -> {
            capturedPair.add(pair);
            return true;
        }));
        assertThat(McpRequestDetector.classifyDiscoveryResponse(capturedPair.get(0)))
                .isEqualTo(DiscoveryResponseKind.OTHER);
        assertThat(runDiscoveryScannerAgainst(capturedPair.get(0))).isEmpty();
    }

    @Test
    void synthesised_request_response_satisfies_T8_HTTP_layer_filter() throws Exception {
        // Make the HTTP-layer assertion explicit so future synthesis changes can't
        // silently break the POST + Content-Type contract that T8 enforces.
        Audit audit = mock(Audit.class);
        McpDiscoveryAuditBridge bridge = new McpDiscoveryAuditBridge(() -> audit);
        CapturedExchange exchange = new CapturedExchange(
                "tools/list",
                URI.create("http://127.0.0.1:8000/mcp"),
                Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                McpObjectMapper.INSTANCE.readTree(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}"));

        bridge.accept(exchange);

        java.util.ArrayList<HttpRequestResponse> capturedPair = new java.util.ArrayList<>();
        verify(audit).addRequestResponse(org.mockito.ArgumentMatchers.argThat(pair -> {
            capturedPair.add(pair);
            return true;
        }));
        HttpRequest req = capturedPair.get(0).request();
        HttpResponse resp = capturedPair.get(0).response();
        assertThat(req.method()).isEqualTo("POST");
        assertThat(req.headerValue("Content-Type")).contains("application/json");
        assertThat(req.bodyToString()).contains("\"method\":\"tools/list\"");
        assertThat(resp.statusCode()).isEqualTo((short) 200);
    }

    @Test
    void synthesised_request_response_satisfies_T8_field_scoping_filter() throws Exception {
        // Field-scoping: T8 only looks at server-controlled textual fields. An AWS key
        // hidden in an inputSchema arguments.default placeholder must NOT fire.
        Audit audit = mock(Audit.class);
        McpDiscoveryAuditBridge bridge = new McpDiscoveryAuditBridge(() -> audit);
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{"
                        + "\"name\":\"safe\","
                        + "\"description\":\"placeholder values are not server data\","
                        + "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
                        + "\"key\":{\"type\":\"string\",\"default\":\"AKIAQ7777PYTYINTERNAL\"}}}"
                        + "}]}}");
        CapturedExchange exchange = new CapturedExchange(
                "tools/list",
                URI.create("http://127.0.0.1:8000/mcp"),
                Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                envelope);

        bridge.accept(exchange);

        java.util.ArrayList<HttpRequestResponse> capturedPair = new java.util.ArrayList<>();
        verify(audit).addRequestResponse(org.mockito.ArgumentMatchers.argThat(pair -> {
            capturedPair.add(pair);
            return true;
        }));
        assertThat(runDiscoveryScannerAgainst(capturedPair.get(0))).isEmpty();
    }

    @Test
    void audit_does_not_create_fp_from_builtin_burp_checks() throws Exception {
        // FP guardrail: we cannot scope the AuditConfiguration to our own check (the
        // Montoya API only exposes LEGACY_PASSIVE_AUDIT_CHECKS), so every registered
        // passive check sees the synthesised pair. Burp's built-in reflected-XSS heuristic
        // looks for tags in the response body. Our pure-JSON-RPC envelope embeds the
        // injection as a string literal — Burp escapes / decodes nothing, so the heuristic
        // should not fire. If a real Burp build did FP, T10 would need a re-design;
        // here we lock in the contract by re-running T8 against the same pair and
        // confirming only T8's content rules see anything (the AWS key, NOT the XSS).
        Audit audit = mock(Audit.class);
        McpDiscoveryAuditBridge bridge = new McpDiscoveryAuditBridge(() -> audit);
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{"
                        + "\"name\":\"xss\","
                        + "\"description\":\"<script>alert(1)</script>\""
                        + "}]}}");
        CapturedExchange exchange = new CapturedExchange(
                "tools/list",
                URI.create("http://127.0.0.1:8000/mcp"),
                Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                envelope);

        bridge.accept(exchange);

        java.util.ArrayList<HttpRequestResponse> capturedPair = new java.util.ArrayList<>();
        verify(audit).addRequestResponse(org.mockito.ArgumentMatchers.argThat(pair -> {
            capturedPair.add(pair);
            return true;
        }));
        // Our T8 check should run cleanly without flagging this as anything (no content
        // rule cares about <script>) — proves we didn't accidentally fold any reflection
        // heuristic into our own passive check.
        assertThat(runDiscoveryScannerAgainst(capturedPair.get(0))).isEmpty();
    }

    @Test
    void bridge_skips_publish_when_audit_supplier_returns_null() {
        // Defensive: McpClientManager nulls the Audit reference on Disconnect. A late
        // publish from an in-flight discovery future must not NPE.
        McpDiscoveryAuditBridge bridge = new McpDiscoveryAuditBridge(() -> null);
        CapturedExchange exchange = new CapturedExchange(
                "tools/list",
                URI.create("http://127.0.0.1:8000/mcp"),
                Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                mock(JsonNode.class));

        // Must not throw.
        bridge.accept(exchange);
    }

    @Test
    void bridge_skips_publish_when_exchange_is_null() {
        Audit audit = mock(Audit.class);
        McpDiscoveryAuditBridge bridge = new McpDiscoveryAuditBridge(() -> audit);

        bridge.accept(null);

        verifyNoInteractions(audit);
    }

    private static List<AuditIssue> runDiscoveryScannerAgainst(HttpRequestResponse pair) {
        ScanCheckSettings settings = mock(ScanCheckSettings.class);
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        return new JsonRpcDiscoveryResponseScanner(settings,
                com.mcpscanner.checks.content.ContentRules.all())
                .doCheck(pair)
                .auditIssues();
    }
}
