package com.mcpscanner.automation;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpServerConfig;

import java.util.function.Consumer;
import java.util.function.Supplier;

public final class HeadlessConnection {

    private final McpClientManager clientManager;
    private final Consumer<Boolean> burpNetworking;
    private final IdentityHandover identities;
    private final CurrentAuthHolder authHolder;

    public HeadlessConnection(McpClientManager clientManager, Consumer<Boolean> burpNetworking,
                              IdentityHandover identities, CurrentAuthHolder authHolder) {
        this.clientManager = clientManager;
        this.burpNetworking = burpNetworking;
        this.identities = identities;
        this.authHolder = authHolder;
    }

    synchronized <T> T exclusively(Supplier<T> launch) {
        return launch.get();
    }

    HeadlessConnected connect(ConnectCommand command) {
        if (command.useBurpNetworking() != null) {
            burpNetworking.accept(command.useBurpNetworking());
        }
        identities.beforeConnect(command.identities(), command.auth());
        AuthStrategy strategy = command.auth().strategy();
        ConnectResult inventory = clientManager.connect(
                new McpServerConfig(command.endpoint(), command.transport(), strategy));
        identities.afterConnect(command.identities(), inventory.tools());
        authHolder.set(strategy);
        return new HeadlessConnected(inventory, clientManager.scannerSession(), strategy);
    }
}
