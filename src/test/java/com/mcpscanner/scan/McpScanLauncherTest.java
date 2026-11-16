package com.mcpscanner.scan;

import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState;
import burp.api.montoya.burpsuite.TaskExecutionEngine;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.Audit;
import com.mcpscanner.engine.EngineScan;
import com.mcpscanner.engine.McpScanEngine;
import com.mcpscanner.engine.ScanErrors;
import com.mcpscanner.engine.ScanFindings;
import com.mcpscanner.engine.ScanLabel;
import com.mcpscanner.engine.ScanProgress;
import com.mcpscanner.engine.ScanSnapshot;
import com.mcpscanner.engine.ScanStatus;
import com.mcpscanner.identity.discovery.PreComparisonDiscovery;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpRequestNames;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.field.AddedArgumentRegistry;
import com.mcpscanner.scan.field.McpFieldGenerator;
import com.mcpscanner.scan.field.TemplateExpansionRegistry;
import com.mcpscanner.scan.request.ClientRegistrationRequestFactory;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.scan.request.McpHttpRequestFactory;
import com.mcpscanner.scan.request.McpMessage;
import com.mcpscanner.scan.request.McpRequestRenderer;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.RequestGenerator;
import com.mcpscanner.scan.request.SampleSurfaces;
import com.mcpscanner.scan.request.ScanRequestRenderer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.PlainFraming;
import com.mcpscanner.testutil.RawHttpRequestStub;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpScanLauncherTest {

    private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();

    private static final ScanLabel LABEL = new ScanLabel("Scan 1 request", "", "", "", "");

    private static final String ENDPOINT = "https://example.com/mcp";
    private static final Map<String, String> NO_HEADERS = Map.of();

    @Mock private Scanner scanner;
    @Mock private BurpSuite burpSuite;
    @Mock private TaskExecutionEngine taskExecution;
    @Mock private Audit audit;
    @Mock private Logging logging;
    @Mock private McpScanEngine engine;

    private final List<String> renderedRaw = new ArrayList<>();
    private final TemplateExpansionRegistry templateExpansions = new TemplateExpansionRegistry();
    private final McpEventLog eventLog = new McpEventLog(null);
    private McpScanLauncher launcher;

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @BeforeEach
    void setUp() {
        lenient().when(scanner.startAudit(any(AuditConfiguration.class))).thenReturn(audit);
        lenient().when(burpSuite.taskExecutionEngine()).thenReturn(taskExecution);
        lenient().when(taskExecution.getState()).thenReturn(TaskExecutionEngineState.RUNNING);
        launcher = launcherWithRequestIds(new AtomicLong()::incrementAndGet);
    }

    @Test
    void recordsEveryTemplateExpansionItQueuesSoTheProviderCanOfferItsVariables() {
        launchBurpAudit(fullScan());

        assertThat(templateExpansions.variablesIn("file:///docs/name"))
                .extracting(UriTemplateExpansion.Variable::name).containsExactly("name");
        assertThat(templateExpansions.variablesIn("file:///notes.txt")).isEmpty();
    }

    @Test
    void startsOneLegacyActiveAuditAndAddsEveryGeneratedRequestWithoutExplicitOffsets() {
        GeneratedScan scan = fullScan();

        RunningScan result = launchBurpAudit(scan);

        assertThat(result).isEqualTo(new BurpAuditRun(audit));
        verify(scanner).startAudit(any(AuditConfiguration.class));
        verify(audit, times(scan.messages().size())).addRequest(any(HttpRequest.class));
        verify(audit, never()).addRequest(any(HttpRequest.class), anyList());
    }

    @Test
    void everyAuditedRequestCarriesTheLiveSessionHeaders() {
        Map<String, String> session = Map.of("Mcp-Session-Id", "live-session",
                "MCP-Protocol-Version", "2025-06-18", "X-Api-Key", "secret");
        GeneratedScan scan = RequestGenerator.standard().scanAll(SampleSurfaces.withoutRegistration(), family -> true);

        launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, scan, session);

        assertThat(auditedRequests(scan.messages().size())).allSatisfy(request -> {
            assertThat(request.headerValue("Mcp-Session-Id")).isEqualTo("live-session");
            assertThat(request.headerValue("MCP-Protocol-Version")).isEqualTo("2025-06-18");
            assertThat(request.headerValue("X-Api-Key")).isEqualTo("secret");
        });
    }

    @Test
    void everyAuditedRequestAsksBurpToCloseTheConnection() {
        GeneratedScan scan = fullScan();

        launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, scan, NO_HEADERS);

        assertThat(auditedRequests(scan.messages().size()))
                .allSatisfy(request -> assertThat(request.headerValue("Connection")).isEqualTo("close"));
    }

    @Test
    void auditsTheAdvertisedClientRegistrationAgainstTheRegistrationEndpointWithoutSessionHeaders() {
        Map<String, String> session = Map.of("Mcp-Session-Id", "live-session", "X-Api-Key", "secret");
        GeneratedScan scan = RequestGenerator.standard().scanAll(SampleSurfaces.advertisingRegistration(),
                family -> family == RequestFamily.CLIENT_REGISTRATION);

        launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, scan, session);

        HttpRequest registration = auditedRequests(1).get(0);
        assertThat(registration.url()).isEqualTo("https://auth.example.test/oauth/register");
        assertThat(registration.headerValue("Mcp-Session-Id")).isNull();
        assertThat(registration.headerValue("X-Api-Key")).isNull();
        assertThat(renderedRaw).isEmpty();
    }

    @Test
    void emptyMessageListStillStartsAnAudit() {
        launchBurpAudit(new GeneratedScan(List.of(), List.of()));

        verify(scanner).startAudit(any(AuditConfiguration.class));
        verify(audit, never()).addRequest(any(HttpRequest.class));
    }

    @Test
    void logsAuditStartedSummaryAndEachRequestAddedToTheBurpAudit() {
        launchBurpAudit(pingScan(2));

        assertThat(eventLog.snapshot()).anySatisfy(entry -> assertThat(entry.message())
                .isEqualTo("Audit started — 2 requests"));
        verify(logging, times(2)).logToOutput("Added ping to Burp audit");
    }

    @Test
    void auditStartedSummaryUsesSingularForOneRequest() {
        launchBurpAudit(pingScan(1));

        assertThat(eventLog.snapshot()).anySatisfy(entry -> assertThat(entry.message())
                .isEqualTo("Audit started — 1 request"));
    }

    @Test
    void burpAuditStartedWhileBurpTasksArePausedWarnsThatItWillNotRunUntilResumed() {
        when(taskExecution.getState()).thenReturn(TaskExecutionEngineState.PAUSED);

        launchBurpAudit(pingScan(1));

        assertThat(eventLog.snapshot()).anySatisfy(entry -> {
            assertThat(entry.level()).isEqualTo(McpEventLog.Level.WARN);
            assertThat(entry.message()).isEqualTo(BurpTaskExecution.PAUSED_WARNING);
        });
    }

    @Test
    void burpAuditStartedWhileBurpTasksRunLogsNoPauseWarning() {
        launchBurpAudit(pingScan(1));

        assertThat(eventLog.snapshot()).noneMatch(entry -> entry.level() == McpEventLog.Level.WARN);
    }

    @Test
    void onlyTheBurpScannerModeWaitsForPausedBurpTasks() {
        when(taskExecution.getState()).thenReturn(TaskExecutionEngineState.PAUSED);

        assertThat(launcher.waitsForPausedTasks(ScanMode.MCP_AND_BURP)).isTrue();
        assertThat(launcher.waitsForPausedTasks(ScanMode.MCP_ONLY)).isFalse();
    }

    @Test
    void burpScannerModeDoesNotWaitWhileBurpTasksRun() {
        assertThat(launcher.waitsForPausedTasks(ScanMode.MCP_AND_BURP)).isFalse();
    }

    @Test
    void resumingBurpTasksSetsTaskExecutionRunning() {
        launcher.resumePausedTasks(ScanMode.MCP_AND_BURP);

        verify(taskExecution).setState(TaskExecutionEngineState.RUNNING);
    }

    @Test
    void logsEachRequestAddedToTheMcpOnlyScan() {
        engineReturns(new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0));

        launchEngineRun(pingScan(1));

        verify(logging).logToOutput("Added ping to extension scan");
    }

    @Test
    void aRequestBurpRefusesDeletesTheJustStartedAuditAndFailsTheLaunch() {
        IllegalStateException refused = new IllegalStateException("audit refused the request");
        doThrow(refused).when(audit).addRequest(any(HttpRequest.class));

        assertThatThrownBy(() -> launchBurpAudit(pingScan(1))).isSameAs(refused);

        verify(audit).delete();
        assertThat(launcher.activity().isIdle()).isTrue();
    }

    @Test
    void clearingRunningScansForgetsBurpAuditsWithoutDeletingThem() {
        launchBurpAudit(pingScan(1));

        launcher.clearRunningScans();
        launcher.cancelRunningScans();

        verify(audit, never()).delete();
        assertThat(launcher.activity().isIdle()).isTrue();
    }

    @Test
    void clearingRunningScansCancelsEngineRunsBecauseNoDashboardCouldStopThem() {
        EngineScan engineScan = engineReturns(new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0));
        launchEngineRun(pingScan(1));

        launcher.clearRunningScans();

        assertThat(engineScan.snapshot().progress().cancelled()).isTrue();
        assertThat(launcher.activity().isIdle()).isTrue();
    }

    @Test
    void cancellingRunningScansDeletesBurpAudits() {
        launchBurpAudit(pingScan(1));

        launcher.cancelRunningScans();

        verify(audit).delete();
    }

    @Test
    void cancellingRunningScansCancelsEngineRuns() {
        EngineScan engineScan = engineReturns(new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0));
        launchEngineRun(pingScan(1));

        launcher.cancelRunningScans();

        assertThat(engineScan.snapshot().progress().cancelled()).isTrue();
        assertThat(launcher.activity().isIdle()).isTrue();
    }

    @Test
    void capturedScanDiscoversComparedUsersJustBeforeLaunchingNotWhenCaptured() {
        List<String> events = new ArrayList<>();
        launcher = launcherDiscovering(new AtomicLong()::incrementAndGet, () -> events.add("discover"));

        Supplier<RunningScan> captured = launcher.captureScan(ScanMode.MCP_AND_BURP, ENDPOINT, pingScan(1), Map::of,
                ScanConnection.unbound(baseline -> Map.of()));
        assertThat(events).isEmpty();
        captured.get();

        assertThat(events).containsExactly("discover");
        assertThat(renderedRaw).hasSize(1);
    }

    @Test
    void capturedScanCarriesTheConnectionHeadersOfTheSessionItWasCapturedFor() {
        List<Boolean> validated = new ArrayList<>();
        ScanConnection connection = new ScanConnection(
                baseline -> Map.of("X-Mcp-Scanner-Audit-Capability", "token-for-" + baseline.get("Mcp-Session-Id")),
                () -> validated.add(true));

        launcher.captureScan(ScanMode.MCP_AND_BURP, ENDPOINT, pingScan(1),
                () -> Map.of("Mcp-Session-Id", "live"), connection).get();

        assertThat(renderedRaw).singleElement().asString()
                .contains("Mcp-Session-Id: live", "X-Mcp-Scanner-Audit-Capability: token-for-live");
        assertThat(validated).isNotEmpty();
    }

    @Test
    void capturedBurpAuditDoesNotStartWhenItsConnectionHasGone() {
        assertThatThrownBy(() -> launcher.captureScan(ScanMode.MCP_AND_BURP, ENDPOINT, pingScan(1), Map::of,
                retiredConnection()).get())
                .hasMessageContaining("connection changed");
        verify(scanner, never()).startAudit(any(AuditConfiguration.class));
    }

    @Test
    void capturedEngineRunChecksItsConnectionBeforeReachingTheEngine() {
        assertThatThrownBy(() -> launcher.captureScan(ScanMode.MCP_ONLY, ENDPOINT, pingScan(1), Map::of,
                retiredConnection()).get())
                .hasMessageContaining("connection changed");
        verify(engine, never()).scan(anyList(), any());
    }

    @Test
    void capturedScanLaunchesInTheModeItWasCapturedFor() {
        engineReturns(new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0));

        launcher.captureScan(ScanMode.MCP_ONLY, ENDPOINT, pingScan(1), Map::of, launcher.captureConnection()).get();
        launcher.captureScan(ScanMode.MCP_AND_BURP, ENDPOINT, pingScan(1), Map::of,
                launcher.captureConnection()).get();

        verify(engine).scan(anyList(), any());
        verify(scanner).startAudit(any(AuditConfiguration.class));
    }

    @Test
    void aBurpAuditReportsItsRequestsAndIssues() {
        when(audit.requestCount()).thenReturn(3);
        when(audit.issues()).thenReturn(List.of());

        launchBurpAudit(pingScan(1));

        assertThat(launcher.activity()).isEqualTo(ScanActivity.burpAudit(3, 0));
    }

    @Test
    void anEngineRunReportsTheInvocationsItHasRunAsProbesRun() {
        engineReturns(runningEngineScan(new ScanProgress(10, 4, 0, 2, false)));

        launchEngineRun(pingScan(2));

        assertThat(launcher.activity()).isEqualTo(ScanActivity.mcpOnlyScan(4, 2));
    }

    @Test
    void activityCountsRunningEngineRunsBesideBurpAudits() {
        when(audit.requestCount()).thenReturn(3);
        when(audit.issues()).thenReturn(List.of());
        engineReturns(runningEngineScan(new ScanProgress(10, 4, 0, 2, false)));

        launchBurpAudit(pingScan(2));
        launchEngineRun(pingScan(2));

        assertThat(launcher.activity()).isEqualTo(new ScanActivity(1, 3, 1, 4, 2));
    }

    @Test
    void finishedEngineRunsNoLongerCountAsActivity() {
        EngineScan engineScan = engineReturns(new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0));
        launchEngineRun(pingScan(1));

        engineScan.completion().complete(engineScan.snapshot().progress());

        assertThat(launcher.activity().isIdle()).isTrue();
    }

    @Test
    void engineRunsReceiveTheRenderedRequestsWithoutResponses() {
        engineReturns(new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0));

        launchEngineRun(pingScan(2));

        assertThat(engineBases()).hasSize(2).allSatisfy(base -> assertThat(base.response()).isNull());
    }

    @Test
    void engineRunsGetTheSameRenderedRequestsAsTheBurpAudit() {
        engineReturns(new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0));
        McpScanLauncher fixedIds = launcherWithRequestIds(() -> 1L);
        GeneratedScan scan = RequestGenerator.standard().scanAll(SampleSurfaces.withoutRegistration(), family -> true);

        fixedIds.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, scan, NO_HEADERS);
        fixedIds.launchScan(ScanMode.MCP_ONLY, ENDPOINT, scan, NO_HEADERS);

        assertThat(engineBases()).extracting(HttpRequestResponse::request).extracting(HttpRequest::toString)
                .containsExactlyElementsOf(auditedRequests(scan.messages().size()).stream()
                        .map(HttpRequest::toString).toList());
    }

    @Test
    void aProbeCallsRenderedBodyIsRegisteredWithTheArgumentItAdded() {
        engineReturns(new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0));
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        McpScanLauncher probing = new McpScanLauncher(logging,
                new ScanRequestRenderer((endpoint, message, sessionHeaders) -> RawHttpRequestStub.fromRaw(
                        new McpHttpRequestFactory(() -> 1L, PlainFraming.framer())
                                .raw(endpoint, message, sessionHeaders)), new ClientRegistrationRequestFactory()),
                () -> ScanConnection.unbound(baseline -> Map.of()), templateExpansions, addedArguments,
                ScanDestinations.of(scanner, burpSuite, eventLog,
                        new EngineScans(engine, new ScanLabels(FixedConnectionFacts.NONE, new McpRequestNames())), () -> { }),
                new RunningScans(eventLog, burpSuite), PreComparisonDiscovery.NONE);
        McpMessage probe = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "t")).withAddedArgument(ArgumentPath.of("a", "b"));

        probing.launchScan(ScanMode.MCP_ONLY, ENDPOINT, new GeneratedScan(List.of(probe), List.of()), NO_HEADERS);

        assertThat(engineBases()).hasSize(1).allSatisfy(base -> assertThat(
                addedArguments.addedTo(base.request().bodyToString())).contains(ArgumentPath.of("a", "b")));
    }

    @Test
    void aNestedLeafOfAScannedToolBecomesTheOnlyInsertionPointOfItsProbeCall() {
        engineReturns(new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0));
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        McpScanLauncher launcher = launcherRecordingIn(addedArguments);
        McpToolDefinition tool = new McpToolDefinition("list_rows", "d", "{\"type\":\"object\",\"properties\":"
                + "{\"filter\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},"
                + "\"ref\":{\"type\":\"string\",\"pattern\":\"^[a-z]+$\"}}}}}");

        launcher.launchScan(ScanMode.MCP_ONLY, ENDPOINT, RequestGenerator.standard().scanThisRequest(
                RequestFamily.TOOLS_CALL, ScanInventory.toolsOnly(List.of(tool))), NO_HEADERS);

        McpFieldGenerator fields = new McpFieldGenerator(() -> true, templateExpansions,
                BurpNativeJsonRpcFields.ABSENT, addedArguments);
        assertThat(engineBases()).extracting(base -> fields.fieldsOf(base.request()).stream()
                .map(AuditInsertionPoint::name).filter(name -> name.endsWith("filter.ref")).toList())
                .containsExactly(List.of(), List.of("MCP field: params.arguments.filter.ref"));
        assertThat(engineBases()).extracting(base -> addedArguments.isProbe(base.request().bodyToString()))
                .containsExactly(false, true);
    }

    @Test
    void aScansProbeCallsAreForgottenOnceItEnds() {
        EngineScan engineScan = new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0);
        engineReturns(engineScan);
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        McpScanLauncher launcher = launcherRecordingIn(addedArguments);
        McpMessage probe = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "t")).withAddedArgument(ArgumentPath.of("a", "b"));
        launcher.launchScan(ScanMode.MCP_ONLY, ENDPOINT, new GeneratedScan(List.of(probe), List.of()), NO_HEADERS);
        String probeBody = engineBases().get(0).request().bodyToString();
        assertThat(addedArguments.isProbe(probeBody)).isTrue();

        engineScan.completion().complete(engineScan.snapshot().progress());

        assertThat(addedArguments.isProbe(probeBody)).isFalse();
    }

    @Test
    void aBurpAuditsProbeCallsAreForgottenOnceItHasFinished() {
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        McpScanLauncher launcher = launcherRecordingIn(addedArguments);
        McpMessage probe = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "t")).withAddedArgument(ArgumentPath.of("a", "b"));
        launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, new GeneratedScan(List.of(probe), List.of()), NO_HEADERS);
        String probeBody = auditedRequests(1).get(0).bodyToString();
        assertThat(addedArguments.isProbe(probeBody)).isTrue();

        when(audit.statusMessage()).thenReturn("Finished");
        launcher.activity();

        assertThat(addedArguments.isProbe(probeBody)).isFalse();
    }

    @Test
    void anAuditStillRunningKeepsTheProbeCallsItSharesWithAnAuditThatFinished() {
        Audit finishing = org.mockito.Mockito.mock(Audit.class);
        Audit running = org.mockito.Mockito.mock(Audit.class);
        when(scanner.startAudit(any(AuditConfiguration.class))).thenReturn(finishing, running);
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        McpScanLauncher launcher = launcherRecordingIn(addedArguments);
        McpMessage probe = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "t")).withAddedArgument(ArgumentPath.of("a", "b"));
        GeneratedScan scan = new GeneratedScan(List.of(probe), List.of());
        launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, scan, NO_HEADERS);
        launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, scan, NO_HEADERS);
        ArgumentCaptor<HttpRequest> audited = ArgumentCaptor.forClass(HttpRequest.class);
        verify(finishing).addRequest(audited.capture());
        String probeBody = audited.getValue().bodyToString();

        when(finishing.statusMessage()).thenReturn("Finished");
        launcher.activity();

        assertThat(addedArguments.isProbe(probeBody)).isTrue();
    }

    @Test
    void probeCallsAlreadyRecordedAreReleasedWhenRecordingAnotherOneFails() {
        AddedArgumentRegistry addedArguments = org.mockito.Mockito.spy(new AddedArgumentRegistry());
        org.mockito.Mockito.doCallRealMethod().doThrow(new IllegalStateException("recording failed"))
                .when(addedArguments).record(any(), any());
        McpScanLauncher launcher = launcherRecordingIn(addedArguments);
        McpMessage first = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "first")).withAddedArgument(ArgumentPath.of("a", "b"));
        McpMessage second = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "second")).withAddedArgument(ArgumentPath.of("a", "b"));

        assertThatThrownBy(() -> launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT,
                new GeneratedScan(List.of(first, second), List.of()), NO_HEADERS))
                .isInstanceOf(IllegalStateException.class);

        ArgumentCaptor<String> recorded = ArgumentCaptor.forClass(String.class);
        verify(addedArguments, times(2)).record(recorded.capture(), any());
        assertThat(addedArguments.isProbe(recorded.getAllValues().get(0))).isFalse();
    }

    @Test
    void aProbeCallWhoseRecordingFailedIsNeverReleasedBecauseItHoldsNothingOfThisScan() {
        AddedArgumentRegistry addedArguments = org.mockito.Mockito.spy(new AddedArgumentRegistry());
        org.mockito.Mockito.doCallRealMethod().doThrow(new IllegalStateException("recording failed"))
                .when(addedArguments).record(any(), any());
        McpScanLauncher launcher = launcherRecordingIn(addedArguments);
        McpMessage first = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "first")).withAddedArgument(ArgumentPath.of("a", "b"));
        McpMessage second = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "second")).withAddedArgument(ArgumentPath.of("a", "b"));

        assertThatThrownBy(() -> launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT,
                new GeneratedScan(List.of(first, second), List.of()), NO_HEADERS))
                .isInstanceOf(IllegalStateException.class);

        ArgumentCaptor<String> recorded = ArgumentCaptor.forClass(String.class);
        verify(addedArguments, times(2)).record(recorded.capture(), any());
        verify(addedArguments, never()).release(recorded.getAllValues().get(1));
    }

    @Test
    void aCancelledBurpAuditsProbeCallsAreForgotten() {
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        McpScanLauncher launcher = launcherRecordingIn(addedArguments);
        McpMessage probe = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "t")).withAddedArgument(ArgumentPath.of("a", "b"));
        launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, new GeneratedScan(List.of(probe), List.of()), NO_HEADERS);
        String probeBody = auditedRequests(1).get(0).bodyToString();

        launcher.cancelRunningScans();

        assertThat(addedArguments.isProbe(probeBody)).isFalse();
    }

    @Test
    void aBurpAuditOutlivingADisconnectReleasesItsProbeCallsOnceBurpFinishesIt() {
        Audit first = org.mockito.Mockito.mock(Audit.class);
        Audit second = org.mockito.Mockito.mock(Audit.class);
        when(scanner.startAudit(any(AuditConfiguration.class))).thenReturn(first, second);
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        ManualEndPoller polls = new ManualEndPoller();
        McpScanLauncher launcher = launcherRecordingIn(addedArguments, new RunningScans(eventLog, polls, () -> false));
        McpMessage probe = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "t")).withAddedArgument(ArgumentPath.of("a", "b"));
        GeneratedScan scan = new GeneratedScan(List.of(probe), List.of());
        launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, scan, NO_HEADERS);
        launcher.clearRunningScans();
        launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, scan, NO_HEADERS);
        ArgumentCaptor<HttpRequest> audited = ArgumentCaptor.forClass(HttpRequest.class);
        verify(first).addRequest(audited.capture());
        String probeBody = audited.getValue().bodyToString();

        when(first.statusMessage()).thenReturn("Finished");
        polls.runPending();
        assertThat(addedArguments.isProbe(probeBody)).isTrue();
        when(second.statusMessage()).thenReturn("Finished");
        launcher.activity();

        assertThat(addedArguments.isProbe(probeBody)).isFalse();
    }

    @Test
    void aScanThatFailsToStartReleasesTheProbeCallsItRecorded() {
        Audit healthy = org.mockito.Mockito.mock(Audit.class);
        when(scanner.startAudit(any(AuditConfiguration.class)))
                .thenReturn(healthy).thenThrow(new IllegalStateException("no audit"));
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        McpScanLauncher launcher = launcherRecordingIn(addedArguments);
        McpMessage probe = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "t")).withAddedArgument(ArgumentPath.of("a", "b"));
        GeneratedScan scan = new GeneratedScan(List.of(probe), List.of());
        launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, scan, NO_HEADERS);
        ArgumentCaptor<HttpRequest> audited = ArgumentCaptor.forClass(HttpRequest.class);
        verify(healthy).addRequest(audited.capture());
        String probeBody = audited.getValue().bodyToString();

        assertThatThrownBy(() -> launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, scan, NO_HEADERS))
                .isInstanceOf(IllegalStateException.class);
        launcher.cancelRunningScans();

        assertThat(addedArguments.isProbe(probeBody)).isFalse();
    }

    @Test
    void aScanThatFailsWithAnErrorReleasesTheProbeCallsItRecorded() {
        when(scanner.startAudit(any(AuditConfiguration.class))).thenThrow(new AssertionError("fatal"));
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        McpScanLauncher launcher = launcherRecordingIn(addedArguments);
        McpMessage probe = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "t")).withAddedArgument(ArgumentPath.of("a", "b"));

        assertThatThrownBy(() -> launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT,
                new GeneratedScan(List.of(probe), List.of()), NO_HEADERS)).isInstanceOf(AssertionError.class);

        assertThat(addedArguments.addedTo(probeBodyOf(probe))).isEmpty();
    }

    @Test
    void aRenderFailureOnALaterMessageLeavesNoProbeCallRecorded() {
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        McpMessage probe = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "t")).withAddedArgument(ArgumentPath.of("a", "b"));
        McpMessage broken = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "broken"));
        McpHttpRequestFactory factory = new McpHttpRequestFactory(() -> 1L, PlainFraming.framer());
        McpScanLauncher launcher = new McpScanLauncher(logging,
                new ScanRequestRenderer((endpoint, message, sessionHeaders) -> {
                    if (message == broken) {
                        throw new IllegalStateException("cannot render");
                    }
                    return RawHttpRequestStub.fromRaw(factory.raw(endpoint, message, sessionHeaders));
                }, new ClientRegistrationRequestFactory()),
                () -> ScanConnection.unbound(baseline -> Map.of()), templateExpansions, addedArguments,
                ScanDestinations.of(scanner, burpSuite, eventLog,
                        new EngineScans(engine, new ScanLabels(FixedConnectionFacts.NONE, new McpRequestNames())), () -> { }),
                new RunningScans(eventLog, burpSuite), PreComparisonDiscovery.NONE);

        assertThatThrownBy(() -> launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT,
                new GeneratedScan(List.of(probe, broken), List.of()), NO_HEADERS))
                .isInstanceOf(IllegalStateException.class);

        assertThat(addedArguments.addedTo(probeBodyOf(probe))).isEmpty();
    }

    private static String probeBodyOf(McpMessage message) {
        return new McpHttpRequestFactory(() -> 1L, PlainFraming.framer()).build(ENDPOINT, message, NO_HEADERS)
                .bodyToString();
    }

    @Test
    void aNewScanLeavesTheProbeCallsOfAScanStillAuditingAlone() {
        engineReturns(new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0));
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        addedArguments.record("an earlier scan's probe call", ArgumentPath.of("a"));

        launcherRecordingIn(addedArguments).launchScan(ScanMode.MCP_ONLY, ENDPOINT,
                new GeneratedScan(List.of(), List.of()), NO_HEADERS);

        assertThat(addedArguments.isProbe("an earlier scan's probe call")).isTrue();
    }

    @Test
    void aBodyANewScanSendsAsABaseCallStaysTheProbeCallOfTheAuditHoldingItUntilThatAuditEnds() {
        EngineScan holder = new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0);
        when(engine.scan(anyList(), any())).thenReturn(holder,
                new EngineScan(2, LABEL, Clock.systemUTC(), () -> { }, () -> 0));
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        McpScanLauncher launcher = launcherRecordingIn(addedArguments);
        McpMessage probe = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "t")).withAddedArgument(ArgumentPath.of("a", "b"));
        McpMessage base = McpMessage.call(RequestFamily.TOOLS_CALL, "tools/call",
                MAPPER.createObjectNode().put("name", "t"));
        launcher.launchScan(ScanMode.MCP_ONLY, ENDPOINT, new GeneratedScan(List.of(probe), List.of()), NO_HEADERS);
        String probeBody = engineBases().get(0).request().bodyToString();

        launcher.launchScan(ScanMode.MCP_ONLY, ENDPOINT, new GeneratedScan(List.of(base), List.of()), NO_HEADERS);
        assertThat(addedArguments.isProbe(probeBody)).isTrue();

        holder.completion().complete(holder.snapshot().progress());
        assertThat(addedArguments.isProbe(probeBody)).isFalse();
    }

    @Test
    void engineRunsRecordTemplateExpansionsAndStartNoBurpAudit() {
        engineReturns(new EngineScan(1, LABEL, Clock.systemUTC(), () -> { }, () -> 0));

        launchEngineRun(fullScan());

        assertThat(templateExpansions.variablesIn("file:///docs/name"))
                .extracting(UriTemplateExpansion.Variable::name).containsExactly("name");
        verify(scanner, never()).startAudit(any(AuditConfiguration.class));
    }

    private McpScanLauncher launcherRecordingIn(AddedArgumentRegistry addedArguments) {
        return launcherRecordingIn(addedArguments, new RunningScans(eventLog, burpSuite));
    }

    private McpScanLauncher launcherRecordingIn(AddedArgumentRegistry addedArguments, RunningScans runningScans) {
        return new McpScanLauncher(logging,
                new ScanRequestRenderer((endpoint, message, sessionHeaders) -> RawHttpRequestStub.fromRaw(
                        new McpHttpRequestFactory(() -> 1L, PlainFraming.framer())
                                .raw(endpoint, message, sessionHeaders)), new ClientRegistrationRequestFactory()),
                () -> ScanConnection.unbound(baseline -> Map.of()), templateExpansions, addedArguments,
                ScanDestinations.of(scanner, burpSuite, eventLog,
                        new EngineScans(engine, new ScanLabels(FixedConnectionFacts.NONE, new McpRequestNames())), () -> { }),
                runningScans, PreComparisonDiscovery.NONE);
    }

    private McpScanLauncher launcherWithRequestIds(LongSupplier requestIds) {
        return launcherDiscovering(requestIds, PreComparisonDiscovery.NONE);
    }

    private McpScanLauncher launcherDiscovering(LongSupplier requestIds, PreComparisonDiscovery discovery) {
        McpHttpRequestFactory factory = new McpHttpRequestFactory(requestIds::getAsLong, PlainFraming.framer());
        McpRequestRenderer renderer = (endpoint, message, sessionHeaders) -> {
            String raw = factory.raw(endpoint, message, sessionHeaders);
            renderedRaw.add(raw);
            return RawHttpRequestStub.fromRaw(raw);
        };
        return new McpScanLauncher(logging, new ScanRequestRenderer(renderer, new ClientRegistrationRequestFactory()),
                () -> ScanConnection.unbound(baseline -> Map.of()), templateExpansions,
                ScanDestinations.of(scanner, burpSuite, eventLog,
                        new EngineScans(engine, new ScanLabels(FixedConnectionFacts.NONE, new McpRequestNames())), () -> { }),
                new RunningScans(eventLog, burpSuite), discovery);
    }

    private RunningScan launchBurpAudit(GeneratedScan scan) {
        return launcher.launchScan(ScanMode.MCP_AND_BURP, ENDPOINT, scan, NO_HEADERS);
    }

    private RunningScan launchEngineRun(GeneratedScan scan) {
        return launcher.launchScan(ScanMode.MCP_ONLY, ENDPOINT, scan, NO_HEADERS);
    }

    private static GeneratedScan pingScan(int pings) {
        return new GeneratedScan(Collections.nCopies(pings, SampleSurfaces.ping()), List.of());
    }

    private static GeneratedScan fullScan() {
        return RequestGenerator.standard().scanAll(SampleSurfaces.full(), family -> true);
    }

    private static ScanConnection retiredConnection() {
        return new ScanConnection(baseline -> Map.of(), () -> {
            throw new IllegalStateException("MCP connection changed");
        });
    }

    private EngineScan engineReturns(EngineScan engineScan) {
        when(engine.scan(anyList(), any())).thenReturn(engineScan);
        return engineScan;
    }

    private static EngineScan runningEngineScan(ScanProgress progress) {
        EngineScan engineScan = mock(EngineScan.class);
        when(engineScan.snapshot()).thenReturn(new ScanSnapshot(1, LABEL, ScanStatus.RUNNING, Instant.EPOCH,
                Optional.empty(), progress, 0, new ScanErrors(List.of(), 0), List.of(),
                new ScanFindings(List.of(), 0, Map.of())));
        when(engineScan.completion()).thenReturn(new CompletableFuture<>());
        return engineScan;
    }

    private List<HttpRequest> auditedRequests(int expected) {
        ArgumentCaptor<HttpRequest> audited = ArgumentCaptor.forClass(HttpRequest.class);
        verify(audit, times(expected)).addRequest(audited.capture());
        return audited.getAllValues();
    }

    @SuppressWarnings("unchecked")
    private List<HttpRequestResponse> engineBases() {
        ArgumentCaptor<List<HttpRequestResponse>> bases = ArgumentCaptor.forClass(List.class);
        verify(engine).scan(bases.capture(), any());
        return bases.getValue();
    }
}
