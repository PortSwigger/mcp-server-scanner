package com.mcpscanner;

import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.scan.SendToConnectionPolicy;
import com.mcpscanner.scan.request.ClientRegistrationRequestFactory;
import com.mcpscanner.scan.request.McpHttpRequestFactory;
import com.mcpscanner.scan.request.ScanMessageRenderer;
import com.mcpscanner.scan.request.ScanRequestRenderer;

import java.util.List;

record RequestBuildingWiring(CurrentAuthHolder authHolder,
                             ScanMessageRenderer requestRenderer,
                             SendToConnectionPolicy sendToConnections) {

    static RequestBuildingWiring create(ExtensionFoundation foundation, ConnectionWiring connection,
                                        CurrentAuthHolder authHolder) {
        return new RequestBuildingWiring(authHolder, requestRenderer(connection),
                new SendToConnectionPolicy(foundation.configStore()::handleSendToAuthentication,
                        connection.sseProxy()::captureScanConnection, connection.scannerSession()::scannerHeaders));
    }

    private static ScanMessageRenderer requestRenderer(ConnectionWiring connection) {
        return new ScanRequestRenderer(new McpHttpRequestFactory(connection.scannerSession()::nextRequestId,
                connection.operationFramer())::build,
                new ClientRegistrationRequestFactory());
    }

    List<Runnable> sessionResets() {
        return List.of(authHolder::clear);
    }
}
