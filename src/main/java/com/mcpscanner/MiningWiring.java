package com.mcpscanner;

import com.mcpscanner.access.mining.AccessMining;
import com.mcpscanner.access.mining.MiningInputs;
import com.mcpscanner.access.mining.MiningPreferences;
import com.mcpscanner.access.mining.MiningSender;
import com.mcpscanner.access.mining.RoutedMiningSender;
import com.mcpscanner.engine.EngineWorkers;
import com.mcpscanner.identity.OwnedValueStore;
import com.mcpscanner.identity.RegistryOwnedValues;
import com.mcpscanner.scan.McpRepeaterRequestFactory;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class MiningWiring {

    private final ConnectedInventory inventory;
    private final OwnedValueStore ownedValues;
    private final ExecutorService worker;
    private final EngineWorkers sendWorkers;
    private final AccessMining mining;

    private MiningWiring(ExtensionFoundation foundation, AccessWiring access, ConnectedInventory inventory,
                         MiningSender sender) {
        this.inventory = inventory;
        this.ownedValues = new RegistryOwnedValues(foundation.identities());
        this.worker = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "mcp-access-mining");
            thread.setDaemon(true);
            return thread;
        });
        this.sendWorkers = EngineWiring.extensionScanWorkers(foundation.configStore(), "mcp-collect-ids-");
        this.mining = new AccessMining(new MiningInputs(inventory, access.roster(),
                () -> foundation.identities().primaryUser().id()), sender,
                new MiningPreferences(foundation.configStore()), ownedValues, worker, this::resizedSendWorkers,
                foundation.eventLog());
    }

    static MiningWiring create(ExtensionFoundation foundation, ConnectionWiring connection, AccessWiring access,
                               ScanningWiring scanning) {
        ConnectedInventory inventory = new ConnectedInventory();
        connection.clientManager().addConnectListener(inventory::connected);
        McpRepeaterRequestFactory primaryRequests = access.auditRequests(connection, scanning);
        MiningSender sender = new RoutedMiningSender(call -> primaryRequests.requestFor(call.message()),
                access.identityRequests(), connection.burpHttp());
        return new MiningWiring(foundation, access, inventory, sender);
    }

    static MiningWiring withSender(ExtensionFoundation foundation, AccessWiring access, ConnectedInventory inventory,
                                   MiningSender sender) {
        return new MiningWiring(foundation, access, inventory, sender);
    }

    private Executor resizedSendWorkers() {
        sendWorkers.applyWorkerCount();
        return sendWorkers.executor();
    }

    AccessMining mining() {
        return mining;
    }

    OwnedValueStore ownedValues() {
        return ownedValues;
    }

    List<Runnable> sessionResets() {
        return List.of(mining::reset, inventory::disconnected);
    }

    void addShutdownHooks(ShutdownHooks shutdown) {
        shutdown.add("Collecting IDs", () -> {
            mining.cancel();
            worker.shutdownNow();
            sendWorkers.executor().shutdownNow();
        });
    }
}
