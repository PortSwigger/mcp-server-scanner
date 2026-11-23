package com.mcpscanner.checks.api;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

public record BrowserConsentObservation(SignedInProbe probe, URI authorizationEndpoint, String clientName,
                                        URI redirectUri, Optional<Duration> codeArrivedAfter) {

    public static final Duration UNATTENDED_ARRIVAL = Duration.ofSeconds(2);

    public BrowserConsentObservation {
        Objects.requireNonNull(probe, "probe must not be null");
        Objects.requireNonNull(authorizationEndpoint, "authorizationEndpoint must not be null");
        Objects.requireNonNull(clientName, "clientName must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        Objects.requireNonNull(codeArrivedAfter, "codeArrivedAfter must not be null");
    }

    public boolean codeWithoutInteraction() {
        return codeArrivedAfter.filter(arrival -> arrival.compareTo(UNATTENDED_ARRIVAL) <= 0).isPresent();
    }

    public boolean codeTooLateToCount() {
        return codeArrivedAfter.isPresent() && !codeWithoutInteraction();
    }
}
