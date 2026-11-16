package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.engine.EngineEnvironment;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.engine.EngineWorkers;
import com.mcpscanner.engine.ResizableWorkers;
import com.mcpscanner.engine.McpScanEngine;
import com.mcpscanner.engine.SkipCause;
import com.mcpscanner.mcp.McpRequestNames;

import java.time.Clock;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

final class EngineWiring {

    private EngineWiring() {
    }

    static McpScanEngine create(MontoyaApi api, ExtensionFoundation foundation, Http http,
                                AuditInsertionPointProvider insertionPoints) {
        return new McpScanEngine(http, insertionPoints, api.siteMap(),
                extensionScanWorkers(foundation.configStore(), "mcp-scan-engine-"),
                new EngineEnvironment(foundation.eventLog(), Clock.systemUTC(), new EngineInstrumentation(),
                        new McpRequestNames()::nameOf, foundation.collaboratorWatch()::watchedCount));
    }

    static void registerChecks(McpScanEngine engine, ScanCheckRegistry checks, ShutdownHooks shutdown) {
        checks.registerWith((check, type) -> engine.register(check, type,
                (invocations, cause) -> checks.invocationsSkipped(check, invocations, reasonFor(cause))));
        shutdown.add("extension scan engine", engine::shutdown);
    }

    private static SkipReason reasonFor(SkipCause cause) {
        return cause == SkipCause.EXTENSION_UNLOADED ? SkipReason.extensionUnloaded() : SkipReason.scanCancelled();
    }

    static EngineWorkers extensionScanWorkers(ExtensionConfigStore configStore, String threadPrefix) {
        return ResizableWorkers.sizedBy(configStore::extensionScanWorkers, daemonThreads(threadPrefix));
    }

    private static ThreadFactory daemonThreads(String threadPrefix) {
        AtomicInteger threadNumber = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, threadPrefix + threadNumber.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }
}
