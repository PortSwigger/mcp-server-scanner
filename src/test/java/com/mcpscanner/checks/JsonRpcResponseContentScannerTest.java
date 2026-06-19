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

class JsonRpcResponseContentScannerTest {

    private static final String AWS_KEY = "AKIAQ7777PYTYINTERNAL";
    private static final String RESPONSE_QUALIFIER =
            ContentFindingIssueBuilder.RESPONSE_SOURCE.nameQualifier();

    private ScanCheckSettings settings;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        settings = mock(ScanCheckSettings.class);
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
    }

    // ---------------------------------------------------------------------------------------
    // Positive cases — secrets leaked in runtime output
    // ---------------------------------------------------------------------------------------

    @Test
    void flags_aws_key_in_tool_call_text_content() {
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":["
                + "{\"type\":\"text\",\"text\":\"deploy key " + AWS_KEY + "\"}]}}";

        List<AuditIssue> issues = run(scanner(), responsePair("tools/call", "deploy", responseBody));

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).name())
                .isEqualTo(new AwsAccessKeyRule().displayName() + RESPONSE_QUALIFIER);
        assertThat(issues.get(0).remediation())
                .contains("Revoke and rotate the exposed credential")
                .contains("handler does not return secrets or PII in its output")
                .doesNotContain("remove it from all MCP metadata")
                .doesNotContain("discovery metadata")
                .doesNotContain("effectively disclosed");
        assertThat(issues.get(0).detail())
                .contains("in MCP responses")
                .doesNotContain("finding(s)");
    }

    @Test
    void flags_secret_in_embedded_resource_text() {
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":["
                + "{\"type\":\"resource\",\"resource\":{\"text\":\"" + AWS_KEY + "\"}}]}}";

        List<AuditIssue> issues = run(scanner(), responsePair("tools/call", "fetch", responseBody));

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).name())
                .isEqualTo(new AwsAccessKeyRule().displayName() + RESPONSE_QUALIFIER);
    }

    @Test
    void flags_pgp_key_in_resources_read_contents() {
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"contents\":["
                + "{\"text\":\"-----BEGIN PGP PRIVATE KEY BLOCK-----\\n\\n"
                + "lQVYBGV3xQ2mZ7vL3pNwT1yU6iO4eC0sD5fG2hJ4kL8mN3qZ7vL9pT1yU6iO4eC0\"}]}}";

        List<AuditIssue> issues = run(scanner(),
                responsePairForResource("resources/read", "file:///secret", responseBody));

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).name())
                .isEqualTo(new PgpPrivateKeyRule().displayName() + RESPONSE_QUALIFIER);
    }

    @Test
    void flags_secret_in_prompt_get_message() {
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"messages\":["
                + "{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":\"" + AWS_KEY + "\"}}]}}";

        List<AuditIssue> issues = run(scanner(), responsePair("prompts/get", "review", responseBody));

        assertThat(issues).hasSize(1);
    }

    @Test
    void flags_secret_in_tool_error_result() {
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"isError\":true,\"content\":["
                + "{\"type\":\"text\",\"text\":\"failed using " + AWS_KEY + "\"}]}}";

        List<AuditIssue> issues = run(scanner(), responsePair("tools/call", "deploy", responseBody));

        assertThat(issues).hasSize(1);
    }

    @Test
    void flags_secret_in_sse_framed_tool_call() {
        String responseBody = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,"
                + "\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + AWS_KEY + "\"}]}}\n\n";

        List<AuditIssue> issues = run(scanner(),
                responsePairWithResponseContentType("tools/call", "deploy", "text/event-stream", responseBody));

        assertThat(issues).hasSize(1);
    }

    // ---------------------------------------------------------------------------------------
    // Negative cases — FP guardrails
    // ---------------------------------------------------------------------------------------

    @Test
    void ignores_credit_card_in_tool_output() {
        // CreditCard is deliberately excluded from the high-precision subset — real tool
        // output legitimately contains card-shaped numbers. The production scanner must
        // not fire on it.
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":["
                + "{\"type\":\"text\",\"text\":\"card 4111 1111 1111 1111\"}]}}";

        List<AuditIssue> issues = run(scanner(), responsePair("tools/call", "pay", responseBody));

        assertThat(issues).isEmpty();
    }

    @Test
    void ignores_secret_in_tools_list_response() {
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{"
                + "\"name\":\"leak\",\"description\":\"" + AWS_KEY + "\"}]}}";

        List<AuditIssue> issues = run(scanner(), responsePair("tools/list", "n/a", responseBody));

        assertThat(issues).isEmpty();
    }

    @Test
    void ignores_non_jsonrpc_rest_response() {
        HttpRequestResponse rr = buildPair("POST", "application/json",
                "{\"username\":\"alice\"}",
                "{\"users\":[{\"key\":\"" + AWS_KEY + "\"}]}", null);

        List<AuditIssue> issues = run(scanner(), rr);

        assertThat(issues).isEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // Wiring guards
    // ---------------------------------------------------------------------------------------

    @Test
    void returns_empty_when_toggle_disabled() {
        when(settings.isEnabled("response-content-scanner", true)).thenReturn(false);
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":["
                + "{\"type\":\"text\",\"text\":\"" + AWS_KEY + "\"}]}}";

        List<AuditIssue> issues = run(scanner(), responsePair("tools/call", "deploy", responseBody));

        assertThat(issues).isEmpty();
    }

    @Test
    void descriptor_uses_response_content_id_and_is_default_enabled() {
        JsonRpcResponseContentScanner check = scanner();

        assertThat(check.descriptor().id()).isEqualTo("response-content-scanner");
        assertThat(check.descriptor().defaultEnabled()).isTrue();
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    private JsonRpcResponseContentScanner scanner() {
        return scannerWith(ContentRules.highPrecisionSecrets());
    }

    private JsonRpcResponseContentScanner scannerWith(List<ContentRule> rules) {
        return new JsonRpcResponseContentScanner(settings, rules);
    }

    private static List<AuditIssue> run(JsonRpcResponseContentScanner scanner, HttpRequestResponse pair) {
        return scanner.doCheck(pair).auditIssues();
    }

    private static HttpRequestResponse responsePair(String method, String toolName, String responseBody) {
        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\","
                + "\"params\":{\"name\":\"" + toolName + "\"}}";
        return buildPair("POST", "application/json", requestBody, responseBody, null);
    }

    private static HttpRequestResponse responsePairForResource(String method, String uri, String responseBody) {
        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\","
                + "\"params\":{\"uri\":\"" + uri + "\"}}";
        return buildPair("POST", "application/json", requestBody, responseBody, null);
    }

    private static HttpRequestResponse responsePairWithResponseContentType(String method, String toolName,
                                                                           String responseContentType,
                                                                           String responseBody) {
        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\","
                + "\"params\":{\"name\":\"" + toolName + "\"}}";
        return buildPair("POST", "application/json", requestBody, responseBody, responseContentType);
    }

    private static HttpRequestResponse buildPair(String httpMethod, String requestContentType,
                                                 String requestBody, String responseBody,
                                                 String responseContentType) {
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
        lenient().when(resp.headerValue("Content-Type")).thenReturn(responseContentType);
        return rr;
    }
}
