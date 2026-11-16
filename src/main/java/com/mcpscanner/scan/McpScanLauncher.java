package com.mcpscanner.scan;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import com.mcpscanner.identity.discovery.PreComparisonDiscovery;
import com.mcpscanner.scan.field.AddedArgumentRegistry;
import com.mcpscanner.scan.field.TemplateExpansionRegistry;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.scan.request.ScanMessage;
import com.mcpscanner.scan.request.ScanMessageRenderer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

public class McpScanLauncher {

    private final Logging logging;
    private final ScanMessageRenderer requestRenderer;
    private final Supplier<ScanConnection> connectionFactory;
    private final TemplateExpansionRegistry templateExpansions;
    private final AddedArgumentRegistry addedArguments;
    private final ScanDestinations destinations;
    private final RunningScans runningScans;
    private final PreComparisonDiscovery discovery;

    public McpScanLauncher(Logging logging, ScanMessageRenderer requestRenderer,
                           Supplier<ScanConnection> connectionFactory, TemplateExpansionRegistry templateExpansions,
                           ScanDestinations destinations, RunningScans runningScans) {
        this(logging, requestRenderer, connectionFactory, templateExpansions, destinations, runningScans,
                PreComparisonDiscovery.NONE);
    }

    public McpScanLauncher(Logging logging, ScanMessageRenderer requestRenderer,
                           Supplier<ScanConnection> connectionFactory, TemplateExpansionRegistry templateExpansions,
                           ScanDestinations destinations, RunningScans runningScans,
                           PreComparisonDiscovery discovery) {
        this(logging, requestRenderer, connectionFactory, templateExpansions, new AddedArgumentRegistry(),
                destinations, runningScans, discovery);
    }

    public McpScanLauncher(Logging logging, ScanMessageRenderer requestRenderer,
                           Supplier<ScanConnection> connectionFactory, TemplateExpansionRegistry templateExpansions,
                           AddedArgumentRegistry addedArguments, ScanDestinations destinations,
                           RunningScans runningScans, PreComparisonDiscovery discovery) {
        this.addedArguments = Objects.requireNonNull(addedArguments);
        this.discovery = Objects.requireNonNull(discovery);
        this.logging = Objects.requireNonNull(logging);
        this.requestRenderer = Objects.requireNonNull(requestRenderer);
        this.connectionFactory = Objects.requireNonNull(connectionFactory);
        this.templateExpansions = Objects.requireNonNull(templateExpansions);
        this.destinations = Objects.requireNonNull(destinations);
        this.runningScans = Objects.requireNonNull(runningScans);
    }

    public ScanConnection captureConnection() {
        return connectionFactory.get();
    }

    public Supplier<RunningScan> captureScan(ScanMode mode, String endpoint, GeneratedScan scan,
                                             Supplier<Map<String, String>> sessionHeaders, ScanConnection connection) {
        Supplier<Map<String, String>> headers = connectionHeaders(sessionHeaders, connection);
        return () -> {
            discovery.discoverMissing();
            return launchScan(mode, endpoint, scan, headers.get());
        };
    }

    public RunningScan launchScan(ScanMode mode, String endpoint, GeneratedScan scan, Map<String, String> headers) {
        ScanDestination destination = destinations.forMode(mode);
        List<HttpRequest> requests = render(destination, endpoint, scan, headers);
        List<String> heldBodies = new ArrayList<>();
        boolean started = false;
        try {
            recordHolds(scan.messages(), requests, heldBodies);
            RunningScan running = runningScans.track(destination.start(requests));
            running.whenEnded(() -> releaseHolds(heldBodies));
            started = true;
            return running;
        } finally {
            if (!started) {
                releaseHolds(heldBodies);
            }
        }
    }

    private void recordHolds(List<ScanMessage> messages, List<HttpRequest> requests, List<String> heldBodies) {
        for (int i = 0; i < messages.size(); i++) {
            String body = requests.get(i).bodyToString();
            Optional<ArgumentPath> added = messages.get(i).addedArgument();
            if (added.isPresent()) {
                addedArguments.record(body, added.get());
                heldBodies.add(body);
            }
        }
    }

    private void releaseHolds(List<String> heldBodies) {
        heldBodies.forEach(addedArguments::release);
    }

    public boolean waitsForPausedTasks(ScanMode mode) {
        return destinations.forMode(mode).waitsForPausedTasks();
    }

    public void resumePausedTasks(ScanMode mode) {
        destinations.forMode(mode).resumePausedTasks();
    }

    public ScanActivity activity() {
        return runningScans.activity();
    }

    public void cancelRunningScans() {
        runningScans.cancelAll();
    }

    public void failRunningScans(String reason) {
        runningScans.failAll(reason);
    }

    public void clearRunningScans() {
        runningScans.clear();
    }

    public void shutdown() {
        runningScans.shutdown();
    }

    private static Supplier<Map<String, String>> connectionHeaders(Supplier<Map<String, String>> sessionHeaders,
                                                                   ScanConnection connection) {
        return () -> {
            connection.requireCurrent();
            Map<String, String> headers = new LinkedHashMap<>(sessionHeaders.get());
            headers.putAll(connection.headers(Map.copyOf(headers)));
            connection.requireCurrent();
            return headers;
        };
    }

    private List<HttpRequest> render(ScanDestination destination, String endpoint, GeneratedScan scan,
                                     Map<String, String> headers) {
        return scan.messages().stream().map(message -> render(destination, message, endpoint, headers)).toList();
    }

    private HttpRequest render(ScanDestination destination, ScanMessage message, String endpoint,
                               Map<String, String> headers) {
        message.templateExpansion().ifPresent(templateExpansions::record);
        HttpRequest request = message.renderWith(requestRenderer, endpoint, headers);
        logging.logToOutput("Added " + message.subject() + " to " + destination.name());
        return request;
    }
}
