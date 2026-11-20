package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DownstreamRouteEscapeIssuesTest {

    private final DownstreamRouteEscapeIssues issues =
            new DownstreamRouteEscapeIssues(DownstreamRouteEscapeDescriptor.DESCRIPTOR);
    private final HttpRequestResponse base = mock(HttpRequestResponse.class);
    private final AuditInsertionPoint insertionPoint = mock(AuditInsertionPoint.class);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("http://target.test/mcp");
        when(request.bodyToString()).thenReturn("{\"method\":\"tools/call\",\"params\":{\"name\":\"get_item\"}}");
        when(base.request()).thenReturn(request);
        when(insertionPoint.name()).thenReturn("MCP field: params.arguments.id");
    }

    @Test
    void issueNamesTheFieldTheValuesAndTheLimitsOfTheEvidence() {
        HttpRequestResponse traversal = mock(HttpRequestResponse.class);
        HttpRequestResponse control = mock(HttpRequestResponse.class);
        RouteDifference difference = new RouteDifference(
                new RouteProbe(List.of("../", ".././"), List.of(".../", "..././"), List.of()),
                List.of(new SentValue("../", traversal), new SentValue(".../", control)), "control");

        AuditIssue issue = issues.issueFor(base, insertionPoint, difference);

        assertThat(issue.name()).isEqualTo(DownstreamRouteEscapeDescriptor.DESCRIPTOR.issueName());
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("tools/call get_item").contains("MCP field: params.arguments.id")
                .contains("&quot;../&quot;").contains("&quot;.././&quot;")
                .contains("&quot;.../&quot;").contains("does not show")
                .contains("repeat").contains("attached requests show the traversal value &quot;../&quot; "
                        + "and the non-traversal value &quot;.../&quot;");
        assertThat(issue.remediation()).isNotBlank();
        assertThat(issue.requestResponses()).containsExactly(base, traversal, control);
    }

    @Test
    void detailNamesTheAttachedContrastValue() {
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        RouteDifference difference = new RouteDifference(
                new RouteProbe(List.of("..", ".."), List.of("...", "...."), List.of(".")),
                List.of(new SentValue("..", exchange), new SentValue("...", exchange), new SentValue(".", exchange)), "control");

        AuditIssue issue = issues.issueFor(base, insertionPoint, difference);

        assertThat(issue.detail()).contains("and the current-segment value &quot;.&quot;");
        assertThat(issue.requestResponses()).hasSize(4);
    }
}
