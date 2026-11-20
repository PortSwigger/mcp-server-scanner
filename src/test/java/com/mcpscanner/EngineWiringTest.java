package com.mcpscanner;

import com.mcpscanner.testutil.InMemoryPreferences;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.registry.CheckInstrumentation;
import com.mcpscanner.engine.McpScanEngine;
import com.mcpscanner.engine.ScanLabel;
import com.mcpscanner.engine.ScanProgress;
import com.mcpscanner.engine.SkippedInvocations;
import com.mcpscanner.identity.discovery.IdentityListings;
import com.mcpscanner.scan.RunningScan;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.RequestGenerator;
import com.mcpscanner.scan.request.SampleSurfaces;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;
import java.util.stream.IntStream;

import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EngineWiringTest {

    private static final String ENDPOINT = "https://example.test/mcp";

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final ShutdownHooks shutdown = new ShutdownHooks(failure -> { });
    private ExtensionFoundation foundation;
    private ScanningWiring scanning;
    private McpScanEngine engine;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        PersistedObject savedSettings = InMemoryPersistedObject.create();
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.persistence().preferences()).thenReturn(new InMemoryPreferences());
        foundation = ExtensionFoundation.create(api);
        ConnectionWiring connection = ConnectionWiring.create(api, foundation);
        AccessWiring access = AccessWiring.create(foundation, connection, new IdentityListings());
        ScanFoundation scan = ScanFoundation.create(api, foundation, connection);
        engine = scan.engine();
        scanning = ScanningWiring.create(api, foundation, connection,
                RequestBuildingWiring.create(foundation, connection, access.authHolder()), access, scan,
                CheckInstrumentation.NONE, UnaryOperator.identity(),
                com.mcpscanner.checks.api.SignedInConsent.OPTED_OUT);
        EngineWiring.registerChecks(engine, scanning.checkRegistry(), shutdown);
    }

    @AfterEach
    void unload() {
        shutdown.extensionUnloaded();
    }

    @Test
    void engineGetsEveryCheckBurpGetsWithTheSameScanCheckType() {
        McpScanEngine engineSeam = mock(McpScanEngine.class);

        EngineWiring.registerChecks(engineSeam, scanning.checkRegistry(), shutdown);

        assertThat(registrationsOf(engineSeam)).isNotEmpty().containsExactlyElementsOf(registrationsWithBurp());
    }

    @Test
    void unloadingTheExtensionShutsTheEngineDown() {
        shutdown.extensionUnloaded();

        assertThat(engine.scan(List.of(mock(HttpRequestResponse.class)), new ScanLabel("Scan 1 request", "", "", "", "")).completion())
                .isCompletedWithValueMatching(ScanProgress::cancelled);
    }

    @Test
    void mcpOnlyScansFromTheTabRunOnTheEngineTheUnloadHookShutsDown() {
        answerEveryBaseRequest();
        switchOffEveryCatalogCheck();
        CountingCheck check = CountingCheck.unheld();
        engine.register(check, ScanCheckType.PER_REQUEST);

        RunningScan launched = launchOneRequestFromTheTab();
        await().atMost(ofSeconds(10)).until(launched::isFinished);
        shutdown.extensionUnloaded();
        RunningScan afterUnload = launchOneRequestFromTheTab();

        assertThat(check.invocations()).isEqualTo(1);
        assertThat(afterUnload.isFinished()).isTrue();
        verify(api.scanner(), never()).startAudit(any());
    }

    private void switchOffEveryCatalogCheck() {
        scanning.catalog().all().forEach(check ->
                foundation.checkSettings().setEnabled(check.descriptor().id(), false));
    }

    private void answerEveryBaseRequest() {
        when(api.http().sendRequest(any(HttpRequest.class))).thenAnswer(call -> answered(call.getArgument(0)));
    }

    private static HttpRequestResponse answered(HttpRequest request) {
        HttpRequestResponse answered = mock(HttpRequestResponse.class, RETURNS_DEEP_STUBS);
        when(answered.request()).thenReturn(request);
        when(answered.hasResponse()).thenReturn(true);
        return answered;
    }

    @Test
    void disconnectingMidwayThroughAnMcpOnlyScanCancelsIt() {
        answerEveryBaseRequest();
        switchOffEveryCatalogCheck();
        CountDownLatch release = new CountDownLatch(1);
        CountingCheck check = CountingCheck.heldUntil(release);
        engine.register(check, ScanCheckType.PER_REQUEST);
        RunningScan launched = launchOneRequestFromTheTab();
        await().atMost(ofSeconds(10)).until(() -> check.invocations() == 1);

        scanning.sessionResets().forEach(Runnable::run);
        release.countDown();

        await().atMost(ofSeconds(10)).until(launched::isFinished);
        assertThat(foundation.eventLog().snapshot())
                .anySatisfy(entry -> assertThat(entry.message()).contains("cancelled —"));
    }

    private RunningScan launchOneRequestFromTheTab() {
        return scanning.scanLauncher().launchScan(ScanMode.MCP_ONLY, ENDPOINT,
                RequestGenerator.standard().scanAll(SampleSurfaces.advertisingRegistration(),
                        family -> family == RequestFamily.CLIENT_REGISTRATION), Map.of());
    }

    private List<Registration> registrationsWithBurp() {
        RegistrationCaptor captured = new RegistrationCaptor();
        verify(api.scanner(), atLeastOnce())
                .registerActiveScanCheck(captured.checks.capture(), captured.types.capture());
        return captured.registrations();
    }

    private static List<Registration> registrationsOf(McpScanEngine engineSeam) {
        RegistrationCaptor captured = new RegistrationCaptor();
        verify(engineSeam, atLeastOnce()).register(captured.checks.capture(), captured.types.capture(),
                any(SkippedInvocations.class));
        return captured.registrations();
    }

    private record Registration(ActiveScanCheck check, ScanCheckType type) {
    }

    private static final class RegistrationCaptor {

        private final ArgumentCaptor<ActiveScanCheck> checks = ArgumentCaptor.forClass(ActiveScanCheck.class);
        private final ArgumentCaptor<ScanCheckType> types = ArgumentCaptor.forClass(ScanCheckType.class);

        private List<Registration> registrations() {
            return IntStream.range(0, checks.getAllValues().size())
                    .mapToObj(index -> new Registration(checks.getAllValues().get(index),
                            types.getAllValues().get(index)))
                    .toList();
        }
    }

    private static final class CountingCheck implements ActiveScanCheck {

        private final AtomicInteger invocations = new AtomicInteger();
        private final CountDownLatch release;

        private CountingCheck(CountDownLatch release) {
            this.release = release;
        }

        static CountingCheck unheld() {
            return new CountingCheck(new CountDownLatch(0));
        }

        static CountingCheck heldUntil(CountDownLatch release) {
            return new CountingCheck(release);
        }

        int invocations() {
            return invocations.get();
        }

        @Override
        public String checkName() {
            return "counting";
        }

        @Override
        public AuditResult doCheck(HttpRequestResponse base, AuditInsertionPoint insertionPoint, Http http) {
            invocations.incrementAndGet();
            awaitRelease();
            return AuditResult.auditResult(List.of());
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
            return ConsolidationAction.KEEP_BOTH;
        }

        private void awaitRelease() {
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
