package com.mcpscanner.automation;

import com.mcpscanner.client.TransportType;

import java.util.Objects;

public record CheckAccessCommand(String endpoint, TransportType transport, CommandAuth auth, Boolean useBurpNetworking,
                                 CommandIdentities identities) implements ConnectCommand {

    public CheckAccessCommand {
        Objects.requireNonNull(endpoint, "endpoint");
        transport = transport == null ? TransportType.AUTO : transport;
        auth = auth == null ? CommandAuth.NONE : auth;
        identities = identities == null ? CommandIdentities.NONE : identities;
    }
}
