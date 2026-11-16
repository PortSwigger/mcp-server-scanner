package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class DownstreamRouteEscapeCheckTest {

    private static final String TOOLS_CALL = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"get_item\",\"arguments\":{\"id\":\"A1\"}}}";

    private final McpEventLog eventLog = new McpEventLog(null);
    private final DownstreamRouteEscapeCheck check = new DownstreamRouteEscapeCheck(eventLog);
    private final Http http = mock(Http.class);
    private final AuditInsertionPoint insertionPoint = mock(AuditInsertionPoint.class);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void descriptorIsTheTentativeInformationalInsertionPointCheck() {
        assertThat(check.descriptor().id()).isEqualTo("downstream-route-escape");
        assertThat(check.descriptor().kind()).isEqualTo(CheckKind.INSERTION_POINT);
        assertThat(check.descriptor().headlineSeverity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(check.descriptor().headlineConfidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(check.descriptor().cwes()).extracting(cwe -> cwe.id()).containsExactly(22);
        assertThat(check.descriptor().references()).isEmpty();
        assertThat(check.requiresReply()).isTrue();
    }

    @Test
    void baseCallWithoutAReplyIsNotProbed() {
        HttpRequestResponse base = base(TOOLS_CALL, Replies.noResponse());

        assertThat(check.audit(base, insertionPoint, http)).isEmpty();
        verifyNoInteractions(http);
        assertThat(skipLines()).singleElement().asString().startsWith("skipped field ")
                .endsWith(" (prerequisite missing: the server gave no reply to the base call)");
    }

    @Test
    void baseCallThatTheServerRejectedIsStillProbedBecauseItsValueMayJustBeUnknown() {
        HttpRequestResponse rejected = Replies.toolError("unexpected status code: 404");
        HttpRequestResponse base = base(TOOLS_CALL, rejected);
        when(insertionPoint.name()).thenReturn("MCP field: params.arguments.id");
        when(insertionPoint.baseValue()).thenReturn("test");
        when(http.sendRequest(any())).thenReturn(rejected);
        HttpRequest probe = base.request();
        when(insertionPoint.buildHttpRequestWithPayload(any())).thenReturn(probe);

        assertThat(check.audit(base, insertionPoint, http)).isEmpty();

        verify(http, atLeastOnce()).sendRequest(any());
    }

    @Test
    void nonCallRequestIsNotProbed() {
        HttpRequestResponse base = base("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\",\"params\":{}}",
                Replies.toolText("ok"));

        assertThat(check.audit(base, insertionPoint, http)).isEmpty();
        verifyNoInteractions(http);
        assertThat(skipLines()).singleElement().asString().startsWith("skipped field ")
                .endsWith(" (not applicable: not a tools/call, prompts/get or resources/read)");
    }

    @Test
    void protocolMetadataFieldsAreNotProbed() {
        HttpRequestResponse base = base(TOOLS_CALL, Replies.toolText("ok"));
        when(insertionPoint.name()).thenReturn("MCP field: params._meta.progressToken");
        when(insertionPoint.baseValue()).thenReturn("mcp-scanner-progress");

        assertThat(check.audit(base, insertionPoint, http)).isEmpty();
        verifyNoInteractions(http);
        assertThat(skipLines()).singleElement().asString()
                .startsWith("skipped field MCP field: params._meta.progressToken of ")
                .endsWith(" (not applicable: protocol metadata field, not a call argument)");
    }

    @Test
    void stopsProbingAFieldAtTheFirstHttp429() {
        HttpRequestResponse base = base(TOOLS_CALL, Replies.toolText("ok"));
        when(insertionPoint.name()).thenReturn("MCP field: params.arguments.id");
        when(insertionPoint.baseValue()).thenReturn("A1");
        HttpRequestResponse tooManyRequests = Replies.exchange(429, "text/plain", "slow down");
        when(http.sendRequest(any())).thenReturn(tooManyRequests);
        HttpRequest probe = base.request();
        when(insertionPoint.buildHttpRequestWithPayload(any())).thenReturn(probe);

        assertThat(check.audit(base, insertionPoint, http)).isEmpty();

        verify(http, times(1)).sendRequest(any());
        assertThat(skipLines()).singleElement().asString()
                .startsWith("stopped field MCP field: params.arguments.id of ")
                .endsWith(" (rate limited: the server answered HTTP 429)");
    }

    @Test
    void issuesForDifferentFieldsAreBothKeptAndRepeatsOfOneFieldAreMerged() {
        AuditIssue first = issue("field a");
        AuditIssue second = issue("field b");

        assertThat(check.consolidate(first, second)).isEqualTo(ConsolidationAction.KEEP_BOTH);
        assertThat(check.consolidate(first, issue("field a"))).isEqualTo(ConsolidationAction.KEEP_EXISTING);
    }

    private List<String> skipLines() {
        String prefix = CheckLog.prefix(DownstreamRouteEscapeDescriptor.DESCRIPTOR.id());
        return eventLog.snapshot().stream()
                .filter(entry -> entry.level() == McpEventLog.Level.INFO)
                .map(McpEventLog.LogEntry::message)
                .filter(message -> message.startsWith(prefix))
                .map(message -> message.substring(prefix.length()))
                .toList();
    }

    private static AuditIssue issue(String detail) {
        AuditIssue issue = mock(AuditIssue.class);
        when(issue.name()).thenReturn(DownstreamRouteEscapeDescriptor.DESCRIPTOR.issueName());
        when(issue.detail()).thenReturn(detail);
        return issue;
    }

    private static HttpRequestResponse base(String body, HttpRequestResponse reply) {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn(body);
        HttpResponse response = reply.response();
        HttpRequestResponse base = mock(HttpRequestResponse.class);
        when(base.request()).thenReturn(request);
        when(base.response()).thenReturn(response);
        return base;
    }
}
