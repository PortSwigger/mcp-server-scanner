package com.mcpscanner.integration;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.config.ResourceCap;
import com.mcpscanner.cvetargets.requests.VerbatimHeaderHttp;
import com.mcpscanner.engine.FakeSiteMap;
import com.mcpscanner.engine.EngineEnvironment;
import com.mcpscanner.engine.McpScanEngine;
import com.mcpscanner.engine.ResizableWorkers;
import com.mcpscanner.engine.ScanInstrumentation;
import com.mcpscanner.engine.ScanLabel;
import com.mcpscanner.integration.slowlink.DelayingRelay;
import com.mcpscanner.integration.slowlink.RelayStopwatch;
import com.mcpscanner.integration.slowlink.Slack;
import com.mcpscanner.integration.slowlink.TargetRequestLog;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.McpInsertionPointProvider;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executors;

@Tag("slow-link")
@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
class SlowLinkIT {

    private static final Duration ONE_WAY_DELAY = Duration.ofMillis(100);
    private static final Slack SLACK = new Slack(Duration.ofMillis(800), Duration.ofMillis(15));
    private static final int CONNECT_CONCURRENCY = 1;
    private static final int EXTENSION_SCAN_WORKERS = (int) ResourceCap.EXTENSION_SCAN_WORKERS.defaultValue();
    private static final int EXTENSION_SCAN_EFFECTIVE_CONCURRENCY = 5;
    private static final int CHECK_ACCESS_EFFECTIVE_CONCURRENCY = 3;
    private static final int COLLECT_IDS_EFFECTIVE_CONCURRENCY = 7;
    private static final String USER_INFO_CALL = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"user_info\",\"arguments\":{\"username\":\"alice\"}}}";

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"STREAMABLE_HTTP", "MODERN_HTTP"})
    void connectFinishesWithinOneRoundTripPerRequest(TransportType transport) throws Exception {
        try (DelayingRelay relay = DelayingRelay.listening(ONE_WAY_DELAY);
             McpCheckItSupport.RunningServer server = behind(relay, McpCheckItSupport.startServer(advertising(relay)))) {
            McpClientManager manager = new McpClientManager(McpEventLog.noop());
            McpServerConfig config = new McpServerConfig(endpoint(relay), transport, new NoAuthStrategy());
            try {
                stopwatch(relay, server).time("Connect over " + transport, CONNECT_CONCURRENCY, SLACK,
                        () -> manager.connect(config));
            } finally {
                manager.shutdown();
            }
        }
    }

    @Test
    void checkAccessOverEveryItemFinishesWithinItsRoundTripBudget() throws Exception {
        try (DelayingRelay relay = DelayingRelay.listening(ONE_WAY_DELAY);
             McpCheckItSupport.RunningServer server = behind(relay,
                     CheckAccessFixture.startServer("vulnerable", advertising(relay)));
             CheckAccessFixture access = CheckAccessFixture.prepare(endpoint(relay))) {
            stopwatch(relay, server).time("Check access over every item",
                    CHECK_ACCESS_EFFECTIVE_CONCURRENCY, SLACK, access::checkAllItems);
        }
    }

    @Test
    void collectIdsForEveryUserFinishesWithinItsRoundTripBudget() throws Exception {
        try (DelayingRelay relay = DelayingRelay.listening(ONE_WAY_DELAY);
             McpCheckItSupport.RunningServer server = behind(relay,
                     McpCheckItSupport.startServer("--default-mode", "safe", "--public-url", relay.baseUrl()));
             CollectIdsFixture collecting = CollectIdsFixture.connect(endpoint(relay))) {
            stopwatch(relay, server).time("Collect IDs for every user", COLLECT_IDS_EFFECTIVE_CONCURRENCY, SLACK,
                    collecting::collect);
        }
    }

    @Test
    void extensionScanOfOneToolCallFinishesWithinItsRoundTripBudget() throws Exception {
        try (DelayingRelay relay = DelayingRelay.listening(ONE_WAY_DELAY);
             McpCheckItSupport.RunningServer server = behind(relay, McpCheckItSupport.startServer(advertising(relay)));
             ScannerProxyFixture proxy = ScannerProxyFixture.connect(endpoint(relay), TransportType.STREAMABLE_HTTP)) {
            Http http = proxy.routed(new VerbatimHeaderHttp());
            HttpRequestResponse base = proxy.sendBase(http, USER_INFO_CALL);
            McpScanEngine engine = engineWithEveryCatalogCheck(http);
            try {
                stopwatch(relay, server).time("Extension scan of one tool call", EXTENSION_SCAN_EFFECTIVE_CONCURRENCY,
                        SLACK, () -> engine.scan(List.of(base), new ScanLabel("Scan 1 request", "slow-link", "Streamable HTTP", "User 1", "http://slow-link")).completion().join());
            } finally {
                engine.shutdown();
            }
        }
    }

    private static McpScanEngine engineWithEveryCatalogCheck(Http http) {
        McpScanEngine engine = new McpScanEngine(http, new McpInsertionPointProvider(), new FakeSiteMap(),
                ResizableWorkers.sizedBy(() -> EXTENSION_SCAN_WORKERS, Executors.defaultThreadFactory()),
                new EngineEnvironment(McpEventLog.noop(), Clock.systemUTC(), ScanInstrumentation.NONE,
                        HttpRequest::url, scanId -> 0));
        CheckCatalog catalog = CheckCatalog.discover(CheckServices.standalone());
        ScanCheckSettings settings = new ScanCheckSettings(InMemoryPersistedObject.configStore());
        catalog.all().stream().map(McpCheck::descriptor)
                .forEach(check -> settings.setEnabled(check.id(), !check.id().startsWith("fixture")));
        new ScanCheckRegistry(catalog, settings, McpEventLog.noop()).registerWith(engine::register);
        return engine;
    }

    private static String[] advertising(DelayingRelay relay) {
        return new String[] {"--public-url", relay.baseUrl()};
    }

    private static McpCheckItSupport.RunningServer behind(DelayingRelay relay, McpCheckItSupport.RunningServer server) {
        relay.forwardTo(new InetSocketAddress(McpCheckItSupport.HOST, server.port()));
        return server;
    }

    private static RelayStopwatch stopwatch(DelayingRelay relay, McpCheckItSupport.RunningServer server) {
        return new RelayStopwatch(relay, new TargetRequestLog("http://" + McpCheckItSupport.HOST + ":" + server.port()));
    }

    private static String endpoint(DelayingRelay relay) {
        return McpCheckItSupport.mcpEndpoint(relay.port());
    }
}
