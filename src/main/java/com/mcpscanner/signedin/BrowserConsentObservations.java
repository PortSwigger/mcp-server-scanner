package com.mcpscanner.signedin;

import com.mcpscanner.checks.api.BrowserConsentObservation;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

public final class BrowserConsentObservations {

    private final List<BrowserConsentObservation> observations = new CopyOnWriteArrayList<>();

    public void record(BrowserConsentObservation observation) {
        observations.add(Objects.requireNonNull(observation, "observation must not be null"));
    }

    public List<BrowserConsentObservation> at(URI authorizationEndpoint) {
        return observations.stream()
                .filter(observation -> observation.authorizationEndpoint().equals(authorizationEndpoint))
                .toList();
    }

    public void clear() {
        observations.clear();
    }
}
