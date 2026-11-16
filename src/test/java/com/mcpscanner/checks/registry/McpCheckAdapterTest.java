package com.mcpscanner.checks.registry;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.api.InsertionPointCheck;
import com.mcpscanner.checks.api.RecordingChecks;
import com.mcpscanner.checks.api.RequestCheck;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.http.ExchangeLease;
import com.mcpscanner.http.OutsideBurpSends;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class McpCheckAdapterTest {

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "demo-active", "Demo", "desc",
            CheckKind.REQUEST, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
            true, List.of());

    private final HttpRequestResponse base = mock(HttpRequestResponse.class);
    private final Http http = mock(Http.class);
    private final McpEventLog eventLog = new McpEventLog(null);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void checkNameIsDescriptorDisplayName() {
        assertThat(adapterFor(DESCRIPTOR, List.of(), true).checkName()).isEqualTo("Demo");
    }

    @Test
    void checkNameUsesBurpIssueNameWhenPresent() {
        CheckDescriptor withBurpName = new CheckDescriptor(
                "demo-active", "UI Display", "desc",
                CheckKind.REQUEST, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                true, List.of(), Optional.of("Burp Issue Name"));

        assertThat(adapterFor(withBurpName, List.of(), true).checkName()).isEqualTo("Burp Issue Name");
    }

    @Test
    void constructorRejectsNullSettings() {
        assertThatThrownBy(() -> new RequestCheckAdapter(null, eventLog,
                new RecordingChecks.Request(DESCRIPTOR, List.of())))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void logsStartedAndFinishMessagesOnSuccessfulRun() {
        adapterFor(DESCRIPTOR, List.of(mock(AuditIssue.class)), true).doCheck(base, null, http);

        assertThat(infos()).hasSize(2);
        assertThat(infos().get(0)).isEqualTo("Scan check: demo-active — started");
        assertThat(infos().get(1)).startsWith("Scan check: demo-active — finished in ").endsWith("ms, 0 requests, 1 issue");
    }

    @Test
    void checksSendEveryProbeAskingBurpToCloseTheConnection() {
        RecordingChecks.Request check = new RecordingChecks.Request(DESCRIPTOR, List.of());
        new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog, check).doCheck(base, null, http);

        check.calls.get(0).http().sendRequest(HttpRequest.httpRequestFromUrl("https://mcp.example.com/mcp"));

        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).sendRequest(sent.capture());
        assertThat(sent.getValue().headerValue("Connection")).isEqualTo("close");
    }

    @Test
    void finishLineCountsTheProbesTheInvocationSent() {
        RequestCheck sendingTwice = new SendingCheck(2);

        new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog, sendingTwice).doCheck(base, null, http);

        assertThat(infos().get(1)).matches("Scan check: demo-active — finished in \\d+ms, 2 requests, 0 issues");
    }

    @Test
    void finishLineCountsOnceEachProbeTheInvocationSentOutsideBurpFromAnotherThread() {
        RequestCheck reportingFromAWorker = new OutsideBurpCheck(3);

        new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog, reportingFromAWorker)
                .doCheck(base, null, http);

        assertThat(infos().get(1)).matches("Scan check: demo-active — finished in \\d+ms, 3 requests, 0 issues");
    }

    @Test
    void pluralisesIssueCount() {
        adapterFor(DESCRIPTOR, List.of(), true).doCheck(base, null, http);
        adapterFor(DESCRIPTOR, List.of(mock(AuditIssue.class), mock(AuditIssue.class)), true)
                .doCheck(base, null, http);

        assertThat(infos().get(1)).endsWith("ms, 0 requests, 0 issues");
        assertThat(infos().get(3)).endsWith("ms, 0 requests, 2 issues");
    }

    @Test
    void logsOneSkipLineWhenCheckIsDisabled() {
        McpCheckAdapter<?> adapter = adapterFor(DESCRIPTOR, List.of(mock(AuditIssue.class)), false);

        adapter.doCheck(base, null, http);
        adapter.doCheck(base, null, http);

        assertThat(infos()).containsExactly(
                "Scan check: demo-active — skipped a base request without a request (check disabled)");
    }

    @Test
    void logsTheDisabledSkipAgainAfterADisconnect() {
        McpCheckAdapter<?> adapter = adapterFor(DESCRIPTOR, List.of(mock(AuditIssue.class)), false);

        adapter.doCheck(base, null, http);
        adapter.clearConnectionState();
        adapter.doCheck(base, null, http);

        assertThat(infos()).hasSize(2);
    }

    @Test
    void logsSkippedInvocationsOfACancelledScan() {
        McpCheckAdapter<?> adapter = adapterFor(DESCRIPTOR, List.of(), true);

        adapter.invocationsSkipped(3, SkipReason.scanCancelled());
        adapter.invocationsSkipped(1, SkipReason.extensionUnloaded());

        assertThat(infos()).containsExactly(
                "Scan check: demo-active — skipped 3 invocations (scan cancelled)",
                "Scan check: demo-active — skipped 1 invocation (extension unloaded)");
    }

    @Test
    void clearingConnectionStateReachesAConnectionScopedInsertionPointCheck() {
        ScopedInsertionPointCheck check = new ScopedInsertionPointCheck();

        new InsertionPointCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog, check).clearConnectionState();

        assertThat(check.cleared).isTrue();
    }

    @Test
    void instrumentationWrapsTheCheckHttpAndSeesItsIssuesUnderTheCheckId() {
        AuditIssue issue = mock(AuditIssue.class);
        Http instrumented = mock(Http.class);
        List<String> reporters = new ArrayList<>();
        RecordingChecks.Request check = new RecordingChecks.Request(DESCRIPTOR, List.of(issue));
        CheckInstrumentation instrumentation = new CheckInstrumentation() {
            @Override
            public Http probeHttp(String checkId, Http http) {
                reporters.add("http:" + checkId);
                return instrumented;
            }

            @Override
            public void reported(String checkId, List<AuditIssue> issues) {
                reporters.add("issues:" + checkId + ":" + issues.size());
            }
        };

        var result = new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog, check, instrumentation)
                .doCheck(base, null, http);

        assertThat(result.auditIssues()).containsExactly(issue);
        assertThat(check.calls).extracting(RecordingChecks.Call::http).containsExactly(instrumented);
        assertThat(reporters).containsExactly("http:demo-active", "issues:demo-active:1");
    }

    @Test
    void reportedIssuesComeBackWithTheirUpstreamEvidence() {
        HttpRequestResponse proxied = exchange("http://127.0.0.1:40123/mcp");
        HttpRequestResponse upstream = exchange("https://mcp.example.test/mcp");
        AuditIssue issue = AuditIssue.auditIssue("Name", "Detail", "Fix", "https://mcp.example.test/mcp",
                AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, "Background", "Fix background",
                AuditIssueSeverity.HIGH, List.of(proxied));
        List<AuditIssue> reported = new ArrayList<>();
        CheckInstrumentation instrumentation = new CheckInstrumentation() {
            @Override
            public Http probeHttp(String checkId, Http http) {
                return http;
            }

            @Override
            public void reported(String checkId, List<AuditIssue> issues) {
                reported.addAll(issues);
            }
        };
        UpstreamExchanges exchanges = candidate -> candidate == proxied ? Optional.of(upstream) : Optional.empty();

        var result = new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog,
                new RecordingChecks.Request(DESCRIPTOR, List.of(issue)), instrumentation, exchanges)
                .doCheck(base, null, http);

        assertThat(result.auditIssues()).singleElement().satisfies(translated ->
                assertThat(translated.requestResponses()).singleElement()
                        .extracting(HttpRequestResponse::request).isSameAs(upstream.request()));
        assertThat(reported).isEqualTo(result.auditIssues());
    }

    @Test
    void reportedAndLateIssuesCarryNoScannerSentinelHeadersInTheirEvidence() {
        HttpRequestResponse leaking = HttpRequestResponse.httpRequestResponse(
                burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl("https://mcp.example.test/mcp")
                        .withHeader(com.mcpscanner.mcp.ScannerSentinels.AUDIT_CAPABILITY_HEADER, "0.token"),
                burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                        "HTTP/1.1 200 OK\r\n" + com.mcpscanner.mcp.ScannerSentinels.EXCHANGE_HEADER + ": abc\r\n\r\n{}"));
        AuditIssue issue = AuditIssue.auditIssue("Name", "Detail", "Fix", "https://mcp.example.test/mcp",
                AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, "Background", "Fix background",
                AuditIssueSeverity.HIGH, List.of(leaking));
        RequestCheckAdapter adapter = new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog,
                new RecordingChecks.Request(DESCRIPTOR, List.of(issue)));

        List<AuditIssue> issues = new ArrayList<>(adapter.doCheck(base, null, http).auditIssues());
        issues.addAll(adapter.lateIssues(List.of(issue)));

        assertThat(issues).hasSize(2).allSatisfy(reported -> {
            HttpRequestResponse evidence = reported.requestResponses().get(0);
            assertThat(evidence.request().headers()).as("request")
                    .noneMatch(header -> com.mcpscanner.mcp.ScannerSentinels.ALL.contains(header.name()));
            assertThat(evidence.response().headers()).as("response")
                    .noneMatch(header -> com.mcpscanner.mcp.ScannerSentinels.ALL.contains(header.name()));
        });
    }

    @Test
    void theBaseAndEveryProbeReplyStayStoredWhileTheCheckRunsAndAreReleasedWhenItEnds() {
        HttpRequestResponse probeReply = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl("http://127.0.0.1:40123/mcp"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n{}"));
        org.mockito.Mockito.when(http.sendRequest(org.mockito.ArgumentMatchers.any(HttpRequest.class)))
                .thenReturn(probeReply);
        List<HttpRequestResponse> held = new ArrayList<>();
        List<Boolean> heldWhileRunning = new ArrayList<>();
        boolean[] closed = {false};
        UpstreamExchanges exchanges = new UpstreamExchanges() {
            @Override
            public Optional<HttpRequestResponse> upstreamOf(HttpRequestResponse proxied) {
                heldWhileRunning.add(!closed[0] && held.containsAll(List.of(base, probeReply)));
                return Optional.empty();
            }

            @Override
            public ExchangeLease retaining() {
                return new ExchangeLease() {
                    @Override
                    public void hold(HttpRequestResponse proxied) {
                        held.add(proxied);
                    }

                    @Override
                    public com.mcpscanner.http.ExchangeRetention retainBeyondClose() {
                        return com.mcpscanner.http.ExchangeRetention.NONE;
                    }

                    @Override
                    public void close() {
                        closed[0] = true;
                    }
                };
            }
        };
        AuditIssue issue = AuditIssue.auditIssue("Name", "Detail", "Fix", "https://mcp.example.test/mcp",
                AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, "Background", "Fix background",
                AuditIssueSeverity.HIGH, List.of(probeReply));
        RequestCheck sendingAndReporting = new RequestCheck() {
            @Override
            public CheckDescriptor descriptor() {
                return DESCRIPTOR;
            }

            @Override
            public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, Http probes) {
                probes.sendRequest(HttpRequest.httpRequestFromUrl("https://mcp.example.com/mcp"));
                return List.of(issue);
            }
        };

        new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog, sendingAndReporting,
                CheckInstrumentation.NONE, exchanges).doCheck(base, null, http);

        assertThat(heldWhileRunning).containsExactly(true);
        assertThat(closed[0]).isTrue();
    }

    @Test
    void evidenceStillShowingTheProxyHopIsStrippedAndWarnedAbout() {
        HttpRequestResponse leaking = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl("https://mcp.example.test/mcp"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n"
                        + com.mcpscanner.mcp.ScannerSentinels.EXCHANGE_HEADER + ": gone\r\n\r\n{}"));
        AuditIssue issue = AuditIssue.auditIssue("Name", "Detail", "Fix", "https://mcp.example.test/mcp",
                AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, "Background", "Fix background",
                AuditIssueSeverity.HIGH, List.of(leaking));

        adapterFor(DESCRIPTOR, List.of(issue), true).doCheck(base, null, http);

        assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message)
                .anyMatch(message -> message.contains("still shows the proxy hop for 1 exchange"));
    }

    private static HttpRequestResponse exchange(String url) {
        return HttpRequestResponse.httpRequestResponse(ImmutableHttpRequest.post(url, Map.of(), "{}"),
                mock(HttpResponse.class));
    }

    private RequestCheckAdapter adapterFor(CheckDescriptor descriptor, List<AuditIssue> issues, boolean enabled) {
        return new RequestCheckAdapter(AdapterFixtures.settingsAllowing(enabled), eventLog,
                new RecordingChecks.Request(descriptor, issues));
    }

    private List<String> infos() {
        return eventLog.snapshot().stream()
                .filter(entry -> entry.level() == McpEventLog.Level.INFO)
                .map(McpEventLog.LogEntry::message)
                .toList();
    }

    private static final class ScopedInsertionPointCheck implements InsertionPointCheck, ConnectionScoped {

        private boolean cleared;

        @Override
        public CheckDescriptor descriptor() {
            return RecordingChecks.descriptorFor("scoped-ip", CheckKind.INSERTION_POINT);
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse base,
                                      AuditInsertionPoint insertionPoint,
                                      Http http) {
            return List.of();
        }

        @Override
        public void clearConnectionState() {
            cleared = true;
        }
    }

    private record SendingCheck(int probes) implements RequestCheck {

        @Override
        public CheckDescriptor descriptor() {
            return DESCRIPTOR;
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, Http http) {
            for (int probe = 0; probe < probes; probe++) {
                http.sendRequest(HttpRequest.httpRequestFromUrl("https://mcp.example.com/mcp"));
            }
            return List.of();
        }
    }

    private record OutsideBurpCheck(int probes) implements RequestCheck {

        @Override
        public CheckDescriptor descriptor() {
            return DESCRIPTOR;
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, Http http) {
            Thread worker = new Thread(() -> IntStream.range(0, probes)
                    .forEach(probe -> OutsideBurpSends.report(http, baseRequestResponse)));
            worker.start();
            try {
                worker.join();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            return List.of();
        }
    }
}
