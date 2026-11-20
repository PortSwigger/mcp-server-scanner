package com.mcpscanner.cvetargets.identities;

import java.util.Map;
import java.util.Optional;

public record ProvisionedSignedInSession(Map<String, String> cookies, ProvisionedScannerClient scannerClient,
                                         Map<String, String> headers) {

    public ProvisionedSignedInSession {
        cookies = cookies == null ? Map.of() : Map.copyOf(cookies);
        headers = headers == null ? Map.of() : Map.copyOf(headers);
    }

    public Optional<ProvisionedScannerClient> client() {
        return Optional.ofNullable(scannerClient);
    }
}
