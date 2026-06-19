package com.mcpscanner.checks;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.content.ContentFindingIssueBuilder;
import com.mcpscanner.checks.content.ContentRule;
import com.mcpscanner.checks.content.ContentRules;
import com.mcpscanner.checks.content.rules.AwsAccessKeyRule;
import com.mcpscanner.checks.content.rules.CreditCardRule;
import com.mcpscanner.checks.content.rules.IconContentRule;
import com.mcpscanner.checks.content.rules.PgpPrivateKeyRule;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JsonRpcDiscoveryResponseScannerTest {

    private static final String DISCOVERY_QUALIFIER =
            ContentFindingIssueBuilder.DISCOVERY_SOURCE.nameQualifier();

    private ScanCheckSettings settings;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        settings = mock(ScanCheckSettings.class);
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
    }

    // ---------------------------------------------------------------------------------------
    // Positive cases — recover findings the connect-time-only DiscoveryContentScanner missed
    // ---------------------------------------------------------------------------------------

    @Test
    void flags_aws_key_in_tool_description() {
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{"
                + "\"name\":\"leak\","
                + "\"description\":\"Use AKIAQ7777PYTYINTERNAL to authenticate\""
                + "}]}}";

        List<AuditIssue> issues = run(scanner(), discoveryPair("tools/list", responseBody));

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).name())
                .isEqualTo(new AwsAccessKeyRule().displayName() + DISCOVERY_QUALIFIER);
    }

    @Test
    void flags_javascript_icon_in_prompts_list() {
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"prompts\":[{"
                + "\"name\":\"poisoned\","
                + "\"description\":\"safe text\","
                + "\"icons\":[{\"src\":\"javascript:alert(1)\"}]"
                + "}]}}";

        List<AuditIssue> issues = run(scanner(), discoveryPair("prompts/list", responseBody));

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).name())
                .isEqualTo(new IconContentRule().displayName() + DISCOVERY_QUALIFIER);
    }

    @Test
    void flags_pgp_key_in_resource_description() {
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resources\":[{"
                + "\"uri\":\"file:///srv/secret\","
                + "\"name\":\"secret\","
                + "\"description\":\"-----BEGIN PGP PRIVATE KEY BLOCK-----\\n\\n"
                + "lQVYBGV3xQ2mZ7vL3pNwT1yU6iO4eC0sD5fG2hJ4kL8mN3qZ7vL9pT1yU6iO4eC0\""
                + "}]}}";

        List<AuditIssue> issues = run(scanner(), discoveryPair("resources/list", responseBody));

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).name())
                .isEqualTo(new PgpPrivateKeyRule().displayName() + DISCOVERY_QUALIFIER);
    }

    // ---------------------------------------------------------------------------------------
    // Negative cases — FP guardrails. ANY failure here means the implementation is too
    // broad: narrow the field-scoping filter or the classifier instead of relaxing the test.
    // ---------------------------------------------------------------------------------------

    @Test
    void ignores_aws_key_in_tools_call_response() {
        // tools/call returns the tool's RESULT to the caller — that's a user data flow,
        // not a server-leaked secret. Classifier must reject it.
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                + "\"content\":[{\"type\":\"text\",\"text\":\"AKIAQ7777PYTYINTERNAL\"}]"
                + "}}";

        List<AuditIssue> issues = run(scanner(), discoveryPair("tools/call", responseBody));

        assertThat(issues).isEmpty();
    }

    @Test
    void ignores_aws_key_in_argument_schema_default() {
        // Tool's inputSchema property has a placeholder AWS key as the `default` value.
        // That's user-controlled tool configuration metadata, not a server leak.
        // Field-scoping filter must skip schema defaults.
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{"
                + "\"name\":\"benign\","
                + "\"description\":\"safe text\","
                + "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
                + "\"awsKey\":{\"type\":\"string\","
                + "\"default\":\"AKIAQ7777PYTYINTERNAL\"}}}"
                + "}]}}";

        List<AuditIssue> issues = run(scanner(), discoveryPair("tools/list", responseBody));

        assertThat(issues).isEmpty();
    }

    @Test
    void ignores_jwt_shaped_string_in_argument_default() {
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{"
                + "\"name\":\"benign\","
                + "\"description\":\"safe text\","
                + "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
                + "\"token\":{\"type\":\"string\","
                + "\"default\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.signaturePartIsLong\"}}}"
                + "}]}}";

        List<AuditIssue> issues = run(scanner(), discoveryPair("tools/list", responseBody));

        assertThat(issues).isEmpty();
    }

    @Test
    void ignores_credit_card_in_tool_call_test_response() {
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                + "\"content\":[{\"type\":\"text\",\"text\":\"card 4111 1111 1111 1111\"}]"
                + "}}";

        List<AuditIssue> issues = run(scannerWith(List.of(new CreditCardRule())),
                discoveryPair("tools/call", responseBody));

        assertThat(issues).isEmpty();
    }

    @Test
    void ignores_unrelated_json_responses() {
        // Not JSON-RPC at all — a typical REST API response that happens to flow through
        // Burp. The HTTP-layer + MCP-layer filters must both reject it.
        HttpRequestResponse rr = buildPair("POST", "application/json",
                "{\"username\":\"alice\"}",
                "{\"users\":[{\"name\":\"alice\",\"email\":\"AKIAQ7777PYTYINTERNAL@x.com\"}]}");

        List<AuditIssue> issues = run(scanner(), rr);

        assertThat(issues).isEmpty();
    }

    @Test
    void ignores_jsonrpc_non_discovery_responses() {
        // resources/templates/list is a valid MCP method but not in scope for this scanner.
        // Documents the current boundary; a future spec method must not silently widen scope.
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resourceTemplates\":["
                + "{\"uriTemplate\":\"file:///{path}\","
                + "\"description\":\"AKIAQ7777PYTYINTERNAL leak in template\"}]}}";

        List<AuditIssue> issues = run(scanner(),
                discoveryPair("resources/templates/list", responseBody));

        assertThat(issues).isEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // Wiring guards
    // ---------------------------------------------------------------------------------------

    @Test
    void returns_empty_when_master_toggle_disabled() {
        when(settings.isEnabled("discovery-content-scanner", true)).thenReturn(false);
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{"
                + "\"name\":\"leak\","
                + "\"description\":\"AKIAQ7777PYTYINTERNAL\""
                + "}]}}";

        List<AuditIssue> issues = run(scanner(), discoveryPair("tools/list", responseBody));

        assertThat(issues).isEmpty();
    }

    @Test
    void descriptor_uses_discovery_content_master_id() {
        JsonRpcDiscoveryResponseScanner check = scanner();

        assertThat(check.descriptor().id()).isEqualTo("discovery-content-scanner");
        assertThat(check.descriptor().defaultEnabled()).isTrue();
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    private JsonRpcDiscoveryResponseScanner scanner() {
        return scannerWith(ContentRules.all());
    }

    private JsonRpcDiscoveryResponseScanner scannerWith(List<ContentRule> rules) {
        return new JsonRpcDiscoveryResponseScanner(settings, rules);
    }

    private static List<AuditIssue> run(JsonRpcDiscoveryResponseScanner scanner,
                                        HttpRequestResponse pair) {
        AuditResult result = scanner.doCheck(pair);
        return result.auditIssues();
    }

    private static HttpRequestResponse discoveryPair(String method, String responseBody) {
        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\"}";
        return buildPair("POST", "application/json", requestBody, responseBody);
    }

    private static HttpRequestResponse buildPair(String httpMethod, String requestContentType,
                                                 String requestBody, String responseBody) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpResponse resp = mock(HttpResponse.class);
        HttpService service = mock(HttpService.class);
        lenient().when(service.host()).thenReturn("mcp.example.test");
        lenient().when(service.port()).thenReturn(443);
        lenient().when(service.secure()).thenReturn(true);
        lenient().when(rr.request()).thenReturn(req);
        lenient().when(rr.response()).thenReturn(resp);
        lenient().when(req.httpService()).thenReturn(service);
        lenient().when(req.method()).thenReturn(httpMethod);
        lenient().when(req.bodyToString()).thenReturn(requestBody);
        lenient().when(req.headerValue("Content-Type")).thenReturn(requestContentType);
        lenient().when(resp.statusCode()).thenReturn((short) 200);
        lenient().when(resp.bodyToString()).thenReturn(responseBody);
        return rr;
    }
}
