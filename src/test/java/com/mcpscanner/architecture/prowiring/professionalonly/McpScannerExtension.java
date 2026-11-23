package com.mcpscanner.architecture.prowiring.professionalonly;

import burp.api.montoya.MontoyaApi;
import com.mcpscanner.engine.McpScanEngine;

import java.util.Optional;

final class McpScannerExtension {

    Object initialize(MontoyaApi api, Optional<McpScanEngine> engine) {
        return engine.map(this::scansServices).orElse(api.http());
    }

    Optional<ProfessionalFeatures> professional(BurpEdition edition) {
        return ProfessionalFeatures.createIfScanningAvailable(edition);
    }

    private Object scansServices(McpScanEngine engine) {
        return engine.history();
    }
}
