package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import com.mcpscanner.access.CheckAccessRunner;
import com.mcpscanner.automation.AutomationServer;
import com.mcpscanner.automation.CheckAccessProgress;
import com.mcpscanner.automation.CheckAccessSteps;
import com.mcpscanner.automation.ConfirmedAccessRows;
import com.mcpscanner.automation.HeadlessCheckAccess;
import com.mcpscanner.automation.HeadlessConnection;
import com.mcpscanner.automation.HeadlessMining;
import com.mcpscanner.identity.discovery.SettledListings;
import com.mcpscanner.automation.BaseRequestLedger;
import com.mcpscanner.automation.BuiltInTrafficSink;
import com.mcpscanner.automation.CommandSettings;
import com.mcpscanner.automation.HeadlessScanAll;
import com.mcpscanner.automation.IdentityHandover;
import com.mcpscanner.automation.ItemSeeds;
import com.mcpscanner.automation.LaunchedAudit;
import com.mcpscanner.automation.CheckTelemetry;
import com.mcpscanner.automation.SendCanary;
import com.mcpscanner.automation.SinkServer;
import com.mcpscanner.automation.TestAutomationSwitch;
import com.mcpscanner.checks.registry.CheckInstrumentation;
import com.mcpscanner.scan.request.ScanMessageRenderer;

import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.UnaryOperator;

public final class TestAutomationWiring implements ExtensionAutomation {

    private static final String LOOPBACK = "127.0.0.1";
    private static final Duration DISCOVERY_LIMIT = Duration.ofMinutes(5);

    private final TestAutomationSwitch automationSwitch;
    private final CheckTelemetry telemetry = CheckTelemetry.throughTheExtensionProxy();
    private final BaseRequestLedger launchedRequests = new BaseRequestLedger();

    public TestAutomationWiring() {
        this(TestAutomationSwitch.fromSystemProperties());
    }

    TestAutomationWiring(TestAutomationSwitch automationSwitch) {
        this.automationSwitch = automationSwitch;
    }

    @Override
    public CheckInstrumentation instrumentation() {
        return automationSwitch.port().isPresent() ? telemetry : CheckInstrumentation.NONE;
    }

    @Override
    public UnaryOperator<ScanMessageRenderer> launchRenderer() {
        return automationSwitch.port().isPresent() ? launchedRequests::recording : UnaryOperator.identity();
    }

    @Override
    public void startIfSwitchedOn(MontoyaApi api, ExtensionFoundation foundation, ConnectionWiring connection,
                           ScanningWiring scanning, AccessWiring access, MiningWiring mining, ShutdownHooks shutdown) {
        automationSwitch.port().ifPresent(port -> {
            BuiltInTrafficSink diversion = builtInTrafficSink(api, shutdown);
            LaunchedAudit audit = new LaunchedAudit(api.siteMap(), telemetry, diversion::diverted,
                    foundation.collaboratorWatch()::settled);
            CommandSettings settings = new CommandSettings(scanning.checkRegistry(), foundation.checkSettings(),
                    diversion::reset);
            ItemSeeds itemSeeds = new ItemSeeds();
            HeadlessConnection headless = new HeadlessConnection(connection.clientManager(),
                    foundation.configStore()::setUseBurpNetworking, identityHandover(foundation, access, itemSeeds),
                    scanning.authHolder());
            AutomationServer server = new AutomationServer(port, new HeadlessScanAll(headless, settings,
                    scanning.generationSettings(), scanning.scanLauncher(), audit, scanning.scanOwnerArguments()),
                    audit, checkAccess(headless, itemSeeds, connection, scanning, access, mining, shutdown),
                    new SendCanary(connection.burpHttp())).start();
            shutdown.add("Test automation server", server::close);
            api.logging().logToOutput("Test automation listening on 127.0.0.1:" + server.port());
        });
    }

    private static HeadlessCheckAccess checkAccess(HeadlessConnection headless, ItemSeeds itemSeeds,
                                                   ConnectionWiring connection, ScanningWiring scanning,
                                                   AccessWiring access, MiningWiring mining, ShutdownHooks shutdown) {
        CheckAccessProgress progress = new CheckAccessProgress();
        CheckAccessRunner runner = access.runner(connection, scanning, progress.counted(connection.burpHttp()),
                access.siteMapIssues(scanning).andThen(progress), itemSeeds::pinned);
        CheckAccessSteps steps = new CheckAccessSteps(new SettledListings(access.listings(), DISCOVERY_LIMIT)::await,
                new HeadlessMining(mining.mining()::start)::mineEveryUser,
                new ConfirmedAccessRows(access.matrix(), access.confirmations())::rows,
                (rows, listener) -> runner.start(rows, confirmedByTheCommand -> true, listener));
        ExecutorService worker = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "mcp-test-automation-check-access");
            thread.setDaemon(true);
            return thread;
        });
        shutdown.add("Test automation Check access", worker::shutdownNow);
        return new HeadlessCheckAccess(headless, steps, progress, worker);
    }

    private static IdentityHandover identityHandover(ExtensionFoundation foundation, AccessWiring access,
                                                     ItemSeeds itemSeeds) {
        return new IdentityHandover(foundation.identities(), access.confirmations(), access.matrix()::setExpectation,
                itemSeeds::seedWith);
    }

    private BuiltInTrafficSink builtInTrafficSink(MontoyaApi api, ShutdownHooks shutdown) {
        SinkServer sink = SinkServer.start();
        shutdown.add("Test automation built-in check sink", sink::close);
        BuiltInTrafficSink diversion = new BuiltInTrafficSink(launchedRequests,
                () -> HttpService.httpService(LOOPBACK, sink.port(), false));
        api.http().registerHttpHandler(diversion);
        return diversion;
    }
}
