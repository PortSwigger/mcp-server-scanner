package com.mcpscanner.automation;

import com.mcpscanner.scan.OwnerArgumentSource;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.scan.CredentialedHeaders;
import com.mcpscanner.scan.McpScanLauncher;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.ScanPlanner;
import com.mcpscanner.scan.request.AdvertisedAuthorizationServer;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.scan.request.RequestFamilyToggles;
import com.mcpscanner.scan.request.ServerCapabilities;

import java.util.Map;
import java.util.function.Supplier;

public final class HeadlessScanAll {

    private final HeadlessConnection connection;
    private final CommandSettings settings;
    private final RequestFamilyToggles families;
    private final McpScanLauncher launcher;
    private final LaunchedAudit launched;
    private final OwnerArgumentSource ownedObjects;
    private final SeedMessages seeds = new SeedMessages();

    public HeadlessScanAll(HeadlessConnection connection, CommandSettings settings, RequestFamilyToggles families,
                           McpScanLauncher launcher, LaunchedAudit launched, OwnerArgumentSource ownedObjects) {
        this.connection = connection;
        this.settings = settings;
        this.families = families;
        this.launcher = launcher;
        this.launched = launched;
        this.ownedObjects = ownedObjects;
    }

    public LaunchedScan launch(ScanAllCommand command) {
        return connection.exclusively(() -> launchConnected(command));
    }

    private LaunchedScan launchConnected(ScanAllCommand command) {
        settings.apply(command);
        HeadlessConnected connected = connection.connect(command);
        ConnectResult inventory = connected.inventory();
        McpScannerSession session = connected.session();
        LimitedInventory scanned = command.catalogLimit().applyTo(everything(inventory));
        GeneratedScan scan = seeds.appendTo(planner(inventory, session).planSelection(scanned.inventory()),
                command.seeds());
        launched.start(launcher.captureScan(ScanMode.MCP_AND_BURP, session.resolvedEndpoint(), scan,
                CredentialedHeaders.of(session::scannerHeaders, connected.strategy()), launcher.captureConnection()));
        return new LaunchedScan(scan.messages().size(), scanned.notice().orElse(null));
    }

    private ScanPlanner planner(ConnectResult inventory, McpScannerSession session) {
        ServerCapabilities capabilities = new ServerCapabilities(inventory.serverMetadata() == null
                ? Map.of()
                : inventory.serverMetadata().capabilities());
        return new ScanPlanner(families, () -> capabilities, session::negotiatedProtocolVersion,
                AdvertisedAuthorizationServer::none, ownedObjects);
    }

    private static ScanInventory everything(ConnectResult inventory) {
        return new ScanInventory(inventory.tools(), inventory.resources(), inventory.resourceTemplates(),
                inventory.prompts());
    }
}
