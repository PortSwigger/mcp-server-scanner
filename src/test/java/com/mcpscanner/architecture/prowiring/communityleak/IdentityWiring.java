package com.mcpscanner.architecture.prowiring.communityleak;

final class IdentityWiring {

    private final ScanningWiring scanning = new ScanningWiring();

    ScanningWiring scanning() {
        return scanning;
    }
}
