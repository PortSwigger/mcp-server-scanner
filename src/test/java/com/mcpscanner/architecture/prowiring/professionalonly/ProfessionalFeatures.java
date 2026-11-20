package com.mcpscanner.architecture.prowiring.professionalonly;

import burp.api.montoya.MontoyaApi;
import com.mcpscanner.engine.McpScanEngine;

import java.util.Optional;

final class ProfessionalFeatures {

    static Optional<ProfessionalFeatures> createIfScanningAvailable(BurpEdition edition) {
        return edition.scanningAvailable() ? Optional.of(new ProfessionalFeatures()) : Optional.empty();
    }

    Object scanner(MontoyaApi api, McpScanEngine engine) {
        return engine == null ? api.siteMap() : api.scanner();
    }
}
