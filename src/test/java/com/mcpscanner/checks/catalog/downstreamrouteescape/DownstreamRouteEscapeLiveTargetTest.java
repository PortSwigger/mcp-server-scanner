package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.CheckRunner;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.scan.McpInsertionPointProvider;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DownstreamRouteEscapeLiveTargetTest {

    private RecordingRealHttp http;
    private CheckRunner runner;
    private McpCheck check;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        http = new RecordingRealHttp();
        runner = new CheckRunner(http, new McpInsertionPointProvider()::provideInsertionPoints);
        check = CheckCatalog.discover(CheckServices.standalone()).find("downstream-route-escape").orElseThrow();
    }

    @Test
    void isAnInsertionPointCheckThatNeedsAReply() {
        assertThat(check.descriptor().kind()).isEqualTo(CheckKind.INSERTION_POINT);
        assertThat(check.requiresReply()).isTrue();
    }

    @Test
    void rawPathJoinFiresOnlyOnTheRoutedArgumentAsTentativeInformation() throws IOException {
        try (RouteModelServer server = new RouteModelServer(RouteModelServer.PathBuilding.RAW_JOIN)) {
            List<AuditIssue> issues = runner.run(check, baseRequests(server));

            assertThat(issues).hasSize(1);
            AuditIssue issue = issues.get(0);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("params.arguments.id").contains("../").contains(".../");
            assertThat(issue.requestResponses()).hasSize(8);
        }
    }

    @Test
    void fixedRouteSuffixFiresOnlyThroughTheSuffixNeutralisingRetry() throws IOException {
        try (RouteModelServer server = new RouteModelServer(RouteModelServer.PathBuilding.RAW_JOIN_BEFORE_FIXED_SUFFIX)) {
            List<AuditIssue> issues = runner.run(check, baseRequests(server));

            assertThat(issues).hasSize(1);
            assertThat(issues.get(0).detail()).contains("params.arguments.id").contains("../?mcp_route=1");
        }
    }

    @Test
    void firesThoughTheBaseValueIsUnknownToTheServerAndItsCallWasRejected() throws IOException {
        try (RouteModelServer server = new RouteModelServer(
                RouteModelServer.PathBuilding.RAW_JOIN_BEFORE_FIXED_SUFFIX, true)) {
            List<AuditIssue> issues = runner.run(check, List.of(call(server, "get_item", "{\"id\":\"test\"}")));

            assertThat(issues).hasSize(1);
            assertThat(issues.get(0).detail()).contains("params.arguments.id").contains("../?mcp_route=1");
        }
    }

    @Test
    void staysSilentOnAnEncodedSegmentWhenTheBaseValueIsUnknownToTheServer() throws IOException {
        try (RouteModelServer server = new RouteModelServer(RouteModelServer.PathBuilding.ENCODED_SEGMENT, true)) {
            assertThat(runner.run(check, List.of(call(server, "get_item", "{\"id\":\"test\"}")))).isEmpty();
            assertThat(server.requests.get()).isGreaterThan(1);
        }
    }

    @Test
    void encodedSegmentWithDotResolutionFiresThroughTheBareParentProbe() throws IOException {
        try (RouteModelServer server = new RouteModelServer(RouteModelServer.PathBuilding.ENCODED_SEGMENT_RESOLVED)) {
            List<AuditIssue> issues = runner.run(check, baseRequests(server));

            assertThat(issues).hasSize(1);
            assertThat(issues.get(0).detail()).contains("params.arguments.id").contains("&quot;..&quot;");
        }
    }

    @Test
    void fullyEncodedSegmentStaysSilent() throws IOException {
        try (RouteModelServer server = new RouteModelServer(RouteModelServer.PathBuilding.ENCODED_SEGMENT)) {
            assertThat(runner.run(check, baseRequests(server))).isEmpty();
            assertThat(server.requests.get()).isGreaterThan(baseRequests(server).size());
        }
    }

    @Test
    void nonCallRequestsAreNotProbed() throws IOException {
        try (RouteModelServer server = new RouteModelServer(RouteModelServer.PathBuilding.RAW_JOIN)) {
            HttpRequestResponse list = send(server, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\","
                    + "\"params\":{\"cursor\":\"abc\"}}");
            int before = server.requests.get();

            assertThat(runner.run(check, List.of(list))).isEmpty();
            assertThat(server.requests.get()).isEqualTo(before);
        }
    }

    private List<HttpRequestResponse> baseRequests(RouteModelServer server) {
        return List.of(
                call(server, "get_item", "{\"id\":\"A1\"}"),
                call(server, "echo", "{\"text\":\"hello\"}"),
                call(server, "normalize", "{\"path\":\"a/b\"}"));
    }

    private HttpRequestResponse call(RouteModelServer server, String tool, String arguments) {
        return send(server, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\""
                + tool + "\",\"arguments\":" + arguments + "}}");
    }

    private HttpRequestResponse send(RouteModelServer server, String body) {
        return http.sendRequest(HttpRequest.httpRequestFromUrl(server.url())
                .withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withBody(body));
    }
}
