package com.mcpscanner.automation;

import com.mcpscanner.client.TransportType;

interface ConnectCommand {

    String endpoint();

    TransportType transport();

    CommandAuth auth();

    Boolean useBurpNetworking();

    CommandIdentities identities();
}
