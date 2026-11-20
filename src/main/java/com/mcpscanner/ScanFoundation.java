package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Collaborator;
import burp.api.montoya.collaborator.CollaboratorClient;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.engine.McpScanEngine;
import com.mcpscanner.http.TempFileCopies;
import com.mcpscanner.http.WireResolvingCopies;
import com.mcpscanner.logging.McpEventLog;

import java.util.Optional;

record ScanFoundation(CollaboratorWatch collaboratorWatch, ScanFieldWiring fields, McpScanEngine engine) {

    static ScanFoundation create(MontoyaApi api, ExtensionFoundation foundation, ConnectionWiring connection) {
        McpEventLog eventLog = foundation.eventLog();
        CollaboratorWatch collaboratorWatch = new CollaboratorWatch(() -> collaboratorClient(api, eventLog), eventLog,
                new WireResolvingCopies(TempFileCopies.burp(), connection.upstreamExchanges()));
        ScanFieldWiring fields = ScanFieldWiring.create(api, foundation);
        return new ScanFoundation(collaboratorWatch, fields,
                EngineWiring.create(api, foundation, collaboratorWatch, connection.burpHttp(), fields.everyField()));
    }

    private static Optional<CollaboratorClient> collaboratorClient(MontoyaApi api, McpEventLog eventLog) {
        try {
            Collaborator collaborator = api.collaborator();
            return Optional.ofNullable(collaborator).map(Collaborator::createClient);
        } catch (RuntimeException ex) {
            eventLog.info("Collaborator unavailable in this Burp edition: " + ex.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    void addShutdownHooks(ShutdownHooks shutdown) {
        shutdown.add("Collaborator watch", collaboratorWatch::shutdown);
    }
}
