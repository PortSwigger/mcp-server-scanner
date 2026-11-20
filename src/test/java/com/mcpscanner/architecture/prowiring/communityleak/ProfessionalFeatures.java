package com.mcpscanner.architecture.prowiring.communityleak;

import java.util.Optional;

final class ProfessionalFeatures {

    static Optional<ProfessionalFeatures> createIfScanningAvailable() {
        return Optional.of(new ProfessionalFeatures());
    }
}
